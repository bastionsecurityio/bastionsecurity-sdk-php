<?php

namespace Bastion;

class BastionClient
{
    private string $siteKey;
    private string $secret;
    private string $endpoint;
    private int $timeout;

    public function __construct(string $siteKey, string $secret, string $endpoint = 'https://api.bastionsecurity.io', int $timeout = 10)
    {
        $this->siteKey = $siteKey;
        $this->secret = $secret;
        $this->endpoint = rtrim($endpoint, '/');
        $this->timeout = $timeout;
    }

    public function classify(string $token): array
    {
        $body = json_encode(['token' => $token]);
        return $this->post('/v1/classify', $body);
    }

    public function track(string $event, array $data = []): array
    {
        $body = json_encode([
            'event' => $event,
            'data' => $data,
            'site_key' => $this->siteKey,
            'ts' => (int)(microtime(true) * 1000),
        ]);
        return $this->post('/v1/events', $body);
    }

    private function post(string $path, string $body): array
    {
        $signature = hash_hmac('sha256', $body, $this->secret);

        $ch = curl_init($this->endpoint . $path);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'X-Bastion-Site-Key: ' . $this->siteKey,
                'X-Bastion-Signature: ' . $signature,
            ],
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode >= 400) {
            throw new \RuntimeException("Bastion API error: HTTP {$httpCode}");
        }

        return json_decode($response, true) ?: [];
    }
}
