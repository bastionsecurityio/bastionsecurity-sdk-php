<?php
require __DIR__.'/src/BastionError.php';require __DIR__.'/src/BastionClient.php';
use Bastion\BastionClient;use Bastion\BastionError;
$c=json_decode(file_get_contents(getenv('BASTION_QA_SESSION')?:'/tmp/bastion-sdk-qa-session.json'),true,512,JSON_THROW_ON_ERROR);
if(!preg_match('/^http:\/\/(localhost|127\.0\.0\.1):/',$c['endpoint']))throw new RuntimeException('Local QA only');
function check(bool $value):void {if(!$value)throw new RuntimeException('Assertion failed');}
$client=new BastionClient($c['site_key'],$c['secret'],$c['endpoint']);
$fp=$client->fingerprint(['canvas_hash'=>'php-sdk-e2e','platform'=>'MacIntel','user_agent'=>'Mozilla/5.0 Chrome/130.0','language'=>'en-US','languages'=>['en-US']]);check(!empty($fp['token'])&&!empty($fp['expires_at']));
$request=['token'=>$fp['token'],'context'=>['event_type'=>'login','account_id'=>'php-sdk-e2e','login_succeeded'=>false],'idempotency_key'=>bin2hex(random_bytes(16))];
$decision=$client->verify($request);check($client->verify($request)['request_id']===$decision['request_id']);check(is_array($decision['signals']));
check(!empty($client->classify($fp['token'],['event_type'=>'signup','account_id'=>'php-sdk-classify'])['request_id']));
check(!empty($client->track('checkout',['account_id'=>'php-sdk-track','order_amount'=>4,'payment_hash'=>'php-test-card'],$fp['token'])['request_id']));
$request['idempotency_key']=bin2hex(random_bytes(16));$result=$client->batch([$request,['context'=>['event_type'=>'unsupported','account_id'=>'invalid']]]);check($result['accepted']===1&&$result['results'][1]['status']===400);
try{(new BastionClient($c['site_key'],'wrong',$c['endpoint']))->verify($request);throw new RuntimeException('Invalid auth accepted');}catch(BastionError $e){check($e->status===401);}
$challenge=$client->createChallenge(4);$nonce=0;while(!str_starts_with(hash('sha256',$challenge['prefix'].base_convert((string)$nonce,10,36)),str_repeat('0',$challenge['difficulty'])))$nonce++;
check($client->verifyChallenge($challenge['challenge_id'],base_convert((string)$nonce,10,36))['valid']);
try{$client->verifyChallenge($challenge['challenge_id'],base_convert((string)$nonce,10,36));throw new RuntimeException('Replay accepted');}catch(BastionError $e){check($e->status===400);}
echo "PASS: PHP SDK real fingerprint, scoring, deduplication, classify/track, partial batch, auth failure and proof/replay checks.\n";
