<?php
declare(strict_types=1);
namespace Bastion;

class BastionClient
{
    public const DEFAULT_ENDPOINT = 'https://api-production-761a5.up.railway.app/api/antibot';
    private string $endpoint;
    private int $timeout;
    private int $retries;
    public function __construct(private string $siteKey, private string $secret, string $endpoint = self::DEFAULT_ENDPOINT, int $timeout = 15, int $retries = 2)
    {
        $uri = parse_url($endpoint);
        if (!$uri || (($uri['scheme'] ?? '') !== 'https' && !(($uri['scheme'] ?? '') === 'http' && in_array($uri['host'] ?? '', ['localhost','127.0.0.1','[::1]'], true)))) {
            throw new \InvalidArgumentException('Bastion requires HTTPS except on localhost');
        }
        if (isset($uri['user']) || isset($uri['pass']) || isset($uri['query']) || isset($uri['fragment'])) throw new \InvalidArgumentException('Invalid API endpoint');
        if (!$siteKey || !$secret || preg_match('/[\r\n]/', $siteKey.$secret)) throw new \InvalidArgumentException('Valid site credentials are required');
        $this->endpoint = rtrim($endpoint, '/');
        if (empty($uri['path']) || $uri['path'] === '/') $this->endpoint .= '/api/antibot';
        elseif (rtrim($uri['path'], '/') === '/api') $this->endpoint .= '/antibot';
        $this->timeout = min(30, max(1, $timeout));
        $this->retries = min(3, max(0, $retries));
    }
    public function verify(array $request): array
    {
        $request['idempotency_key'] ??= bin2hex(random_bytes(16));
        return $this->post('/verify', $request);
    }
    public function classify(string $token, array $context, array $telemetry = []): array
    {
        return $this->verify(array_merge($telemetry, ['token'=>$token,'context'=>$context]));
    }
    public function track(string $event, array $data, ?string $token = null): array
    {
        return $this->verify(['token'=>$token,'context'=>array_merge($data, ['event_type'=>$event])]);
    }
    public function fingerprint(array $fingerprint, ?array $behavior = null): array
    {
        return $this->post('/verify/fingerprint', ['fingerprint'=>$fingerprint,'behavior'=>$behavior]);
    }
    public function batch(array $events): array
    {
        return $this->post('/verify/batch', ['events'=>array_map(function($e) { $e['idempotency_key'] ??= bin2hex(random_bytes(16)); return $e; }, $events)]);
    }
    public function createChallenge(int $difficulty = 4): array { return $this->post('/verify/challenge', ['difficulty'=>$difficulty]); }
    public function verifyChallenge(string $challengeId, string $nonce): array { return $this->post('/verify/challenge/verify', ['challenge_id'=>$challengeId,'nonce'=>$nonce]); }
    public static function verifyWebhook(string $secret, string $rawBody, string $signature, int $tolerance = 300, ?int $now = null): bool
    {
        $parts = array_map('trim', explode(',', $signature));
        $timestamp = null;
        foreach ($parts as $p) if (preg_match('/^t=([0-9]+)$/D', $p, $m)) { $timestamp = $m[1]; break; }
        if (!$secret || !$timestamp || $tolerance < 0 || abs(($now ?? time()) - (int)$timestamp) > $tolerance) return false;
        $expected = hash_hmac('sha256', $timestamp.'.'.$rawBody, $secret);
        foreach ($parts as $p) if (preg_match('/^v1=([0-9a-f]{64})$/D', $p, $m) && hash_equals($expected, $m[1])) return true;
        return false;
    }
    // json_decode(..., true) loses the distinction between {} and [].
    // Restore object-shaped API fields, leaving actual lists untouched.
    private function jsonObjects(array $body): array
    {
        foreach (['context', 'fingerprint', 'behavior', 'environment', 'headers'] as $field) {
            if (array_key_exists($field, $body) && $body[$field] === []) $body[$field] = new \stdClass();
        }
        if (isset($body['events']) && is_array($body['events'])) {
            $body['events'] = array_map(fn($event) => is_array($event) ? $this->jsonObjects($event) : $event, $body['events']);
        }
        return $body;
    }
    private function post(string $path, array $body): array
    {
        $payload = json_encode($this->jsonObjects($body), JSON_THROW_ON_ERROR);
        $safe = !empty($body['idempotency_key']) || (!empty($body['events']) && count(array_filter($body['events'], fn($e) => !empty($e['idempotency_key']))) === count($body['events']));
        for ($attempt = 0;; $attempt++) {
            $ch = curl_init($this->endpoint.$path);
            curl_setopt_array($ch, [CURLOPT_POST=>true, CURLOPT_POSTFIELDS=>$payload, CURLOPT_RETURNTRANSFER=>true,
                CURLOPT_TIMEOUT=>$this->timeout, CURLOPT_CONNECTTIMEOUT=>$this->timeout, CURLOPT_FOLLOWLOCATION=>false,
                CURLOPT_HTTPHEADER=>['Content-Type: application/json','X-Site-Key: '.$this->siteKey,'X-Secret-Key: '.$this->secret]]);
            $response = curl_exec($ch);
            $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            if ($response === false) $failure = new BastionError('API request could not reach the server');
            else {
                try { $data = json_decode($response, true, 512, JSON_THROW_ON_ERROR); }
                catch (\JsonException $e) { $data = null; }
                if (!is_array($data)) $failure = new BastionError('API returned invalid JSON', $status);
                elseif ($status < 200 || $status >= 300) $failure = new BastionError((string)($data['message'] ?? 'API request failed'), $status, $data);
                elseif (($data['success'] ?? true) === false) $failure = new BastionError('Invalid API response', $status, $data);
                else return $data['data'] ?? $data;
            }
            if (!$safe || $attempt >= $this->retries || ($failure->status > 0 && $failure->status !== 429 && $failure->status < 500)) throw $failure;
            usleep((int)(250000 * 2 ** $attempt));
        }
    }
}
