<?php
require 'vendor/autoload.php';

use Bastion\BastionClient;

function verifyRequest(array $request): array {
    $client = new BastionClient(
        getenv('BASTION_SITE_KEY'),
        getenv('BASTION_SECRET_KEY'),
        getenv('BASTION_ENDPOINT') ?: 'https://api.bastionsecurity.io/api/antibot'
    );
    $decision = $client->verify($request);
    return ['allowed' => $decision['action'] === 'allow', 'decision' => $decision];
}
// Handle Bastion\BastionError without allowing fulfillment.
