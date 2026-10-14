<?php
require __DIR__.'/src/BastionError.php';require __DIR__.'/src/BastionClient.php';
use Bastion\BastionClient;
function check(bool $value): void { if (!$value) throw new RuntimeException('Assertion failed'); }
$body='{"text":"fraud 🚨"}';$secret='secret';$now=12345;$signature='t='.$now.',v1='.hash_hmac('sha256',$now.'.'.$body,$secret);
check(BastionClient::verifyWebhook($secret,$body,$signature,300,$now));
check(!BastionClient::verifyWebhook($secret,$body.' ',$signature,300,$now));
check(!BastionClient::verifyWebhook($secret,$body,$signature,300,$now+301));
try {new BastionClient('public','secret','http://example.com');throw new RuntimeException('Unsafe endpoint accepted');}catch(InvalidArgumentException $e){}
echo "PASS: PHP webhook validation and HTTPS endpoint enforcement.\n";
