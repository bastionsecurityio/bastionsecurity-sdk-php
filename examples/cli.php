<?php
require __DIR__ . '/../vendor/autoload.php';

use Bastion\BastionClient;

function required(string $name): string {
    $value = getenv($name);
    if ($value === false || $value === '') throw new RuntimeException($name . ' is required');
    return $value;
}
function loadJson(string $file): mixed {
    $raw = file_get_contents($file);
    if ($raw === false) throw new RuntimeException('Cannot read input file');
    return json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
}
try {
    $mode = $argv[1] ?? '';
    $status = 0;
    if ($mode === 'webhook') {
        if (count($argv) !== 4) throw new InvalidArgumentException('Usage: webhook raw-body.json signature.txt');
        $raw = file_get_contents($argv[2]);
        $signature = file_get_contents($argv[3]);
        if ($raw === false || $signature === false) throw new RuntimeException('Cannot read delivery or signature file');
        if (!BastionClient::verifyWebhook(required('BASTION_WEBHOOK_SECRET'), $raw, trim($signature))) throw new RuntimeException('Invalid or stale webhook signature');
        $output = ['verified' => true, 'event' => json_decode($raw, true, 512, JSON_THROW_ON_ERROR)];
    } else {
        if (!in_array($mode, ['verify', 'batch', 'challenge'], true)) throw new InvalidArgumentException('Usage: verify telemetry.json order.json | batch requests.json | challenge | webhook raw-body.json signature.txt');
        $client = new BastionClient(required('BASTION_SITE_KEY'), required('BASTION_SECRET_KEY'), getenv('BASTION_ENDPOINT') ?: BastionClient::DEFAULT_ENDPOINT);
        if ($mode === 'verify') {
            if (count($argv) !== 4) throw new InvalidArgumentException('Usage: verify telemetry.json order.json');
            $telemetry = loadJson($argv[2]); $order = loadJson($argv[3]);
            if (empty($telemetry['idempotency_key']) || (empty($telemetry['browser_receipt']) && (empty($telemetry['token']) || empty($telemetry['fingerprint'])))) throw new RuntimeException('Complete buildRequest() telemetry with a stable idempotency_key is required');
            $amount = $order['amount'] ?? null;
            if (!is_string($order['customerId'] ?? null) || $order['customerId'] === '' || !is_string($order['paymentId'] ?? null) || $order['paymentId'] === '' || (!is_int($amount) && !is_float($amount)) || !is_finite((float)$amount) || $amount < 0) throw new RuntimeException('Trusted order needs customerId, paymentId, and a finite nonnegative amount');
            $request = array_intersect_key($telemetry, array_flip(['browser_receipt', 'token', 'fingerprint', 'behavior', 'environment', 'idempotency_key']));
            $request['context'] = ['event_type' => 'checkout', 'account_id' => $order['customerId'], 'order_amount' => $amount, 'payment_hash' => $order['paymentId']];
            $decision = $client->verify($request);
            $output = ['allowed' => $decision['action'] === 'allow', 'decision' => $decision];
        } elseif ($mode === 'batch') {
            if (count($argv) !== 3) throw new InvalidArgumentException('Usage: batch requests.json');
            $requests = loadJson($argv[2]);
            if (!is_array($requests) || !array_is_list($requests) || count($requests) < 1 || count($requests) > 50) throw new RuntimeException('Batch needs 1–50 server-owned requests');
            foreach ($requests as $request) if (empty($request['idempotency_key'])) throw new RuntimeException('Every batch item requires a stable idempotency_key');
            $output = $client->batch($requests);
            foreach ($output['results'] as &$item) {
                $item['allowed'] = ($item['success'] ?? false) === true && ($item['decision']['action'] ?? '') === 'allow';
                if (!$item['success']) $status = 2;
            }
            unset($item);
        } else {
            $challenge = $client->createChallenge(4);
            $deadline = min(microtime(true) + 60, (float)strtotime($challenge['expires_at']));
            $nonce = 0;
            while (!str_starts_with(hash('sha256', $challenge['prefix'] . base_convert((string)$nonce, 10, 36)), str_repeat('0', $challenge['difficulty']))) {
                if (microtime(true) >= $deadline) throw new RuntimeException('Proof solver deadline reached');
                $nonce++;
            }
            $result = $client->verifyChallenge($challenge['challenge_id'], base_convert((string)$nonce, 10, 36));
            if (!$result['valid']) throw new RuntimeException('Proof was rejected');
            $output = $result + ['fulfillment_authorized' => false];
        }
    }
    echo json_encode($output, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR) . "\n";
    exit($status);
} catch (Throwable $error) {
    fwrite(STDERR, 'Example failed: ' . $error->getMessage() . "\n");
    exit(1);
}
