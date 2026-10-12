# Bastion Security PHP SDK

Official PHP SDK for [Bastion Security](https://bastionsecurity.io) — real-time bot detection and fraud prevention.

## Installation

```bash
composer require bastionsecurity/sdk
```

## Usage

```php
use Bastion\BastionClient;

$client = new BastionClient(
    siteKey: 'pk_live_your_site_key',
    secret: 'sk_live_your_secret_key',
);

// Classify a token from the frontend SDK
$result = $client->classify('token-from-frontend');
echo $result['verdict'] . ' — score ' . $result['score'];

// Track a server-side event
$client->track('purchase', ['amount' => 49.99, 'user_id' => 'usr_123']);
```

## API

### `new BastionClient(string $siteKey, string $secret, string $endpoint = '...', int $timeout = 10)`

### `$client->classify(string $token): array`

### `$client->track(string $event, array $data = []): array`

## License

MIT — © 2024 Bastion Security
