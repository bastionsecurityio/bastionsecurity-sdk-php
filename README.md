# Bastion Php SDK (0.2)

Authenticated **server-side** scoring. The browser must use the JavaScript SDK to collect fingerprint, behavior, and environment telemetry; forward its complete `buildRequest()` payload to your server. Never expose the secret key or raw payment credentials to a browser.

Install the current source release: Use Composer with a VCS repository and the development branch:
```json
{"repositories":[{"type":"vcs","url":"https://github.com/bastionsecurityio/sdk-php.git"}],"require":{"bastionsecurity/sdk":"dev-main"}}
```
Run `composer install`. Requires PHP 8.1+, curl, and JSON.. Registry publication is separate from this Git release.

```php
use Bastion\BastionClient;
$client = new BastionClient(getenv('BASTION_SITE_KEY'), getenv('BASTION_SECRET_KEY'));
$request = $browserRequest;
$request['context']['account_id'] = $authenticatedAccountId;
$request['context']['order_amount'] = $validatedAmount;
$decision = $client->verify($request);
if ($decision['action'] !== 'allow') throw new RuntimeException('Challenge or review required');
```

Methods: `verify($request)`, `classify($token, $context, $telemetry=[])`, `track($event, $context, $token=null)`, `fingerprint($hash, $behavior=null)`, `batch($requests)`, `createChallenge($difficulty=4)`, `verifyChallenge($id, $nonce)`. `BastionClient::verifyWebhook($secret, $rawBody, $signature)` verifies exact raw bytes. Errors: `BastionError` with `status` and `response`.

The endpoint defaults to `https://api-production-761a5.up.railway.app/api/antibot`; root URLs and `/api` are normalized. Override it for your deployment. HTTPS is required except on localhost. Server authentication uses `X-Site-Key` and `X-Secret-Key`. A 15-second timeout and two bounded retries apply by default; timeouts/retries are configurable. Redirects never forward your credentials. Network/429/5xx retries preserve the serialized body and idempotency key; validation/auth failures are never retried. Invalid JSON and network errors cannot become an allowed decision.

The full API decision includes `action`, `classification`, `risk_score`, `risk_level`, `signals` (rule, score, evidence description), `identity`, `device_id`, `request_id`, `decision_ms`, `timestamp`, and optional `challenge`. Always enforce `action` **before fulfillment**. A successful single-use proof is site-bound and does not override a block/review decision.

Context requires `event_type` (`signup`, `login`, `promo_claim`, `checkout`, `page_view`) and `account_id`. Optional fields include `email`, `ip_address`, `user_agent`, `payment_hash`, `promo_code`, `order_amount`, `request_url`, and server-verified `login_succeeded`. Preserve the browser's `fingerprint`, `behavior`, `environment`, and optional end-user headers. Overwrite business context with authenticated server values rather than trusting client claims.

Keep `idempotency_key` stable across application-level retries of the **same** request. The API stores scoring receipts for 24 hours and rejects changed payloads under the same key (409). Each batch accepts 1–50 events and returns per-item acknowledgements/errors; inspect every result, and retry failures with their existing keys. Supply explicit keys if you may call `batch` again.

Webhooks are signed HMAC-SHA256 over `timestamp.raw-body` with a five-minute tolerance and constant-time signature comparison. Verify the exact raw bytes before JSON parsing. Persist received event IDs to deduplicate at-least-once deliveries.

0.1 migration: replace `/v1` platform paths and `X-Bastion-*` signatures with the actual `/api/antibot` routes/site credentials and explicit context. Old invented tokens are no longer supported. Dashboard management, billing, SSO, support and teams use the authenticated platform control-plane API, not customer scoring keys. Stripe/Resend/IdP setup is done in the platform.

Unit tests cover signature and error/auth/retry behavior. The `test_e2e` test covers real fingerprint registration, all scoring helpers, durable deduplication, partial batches, invalid keys, and proof verification/replay. Set `BASTION_QA_SESSION` to a fixture from the platform's isolated local test environment; production URLs are rejected.

Make your own fulfillment operation idempotent as well: persist the decision/request ID and never fulfill the same logical checkout twice. API retry receipts deduplicate scoring, not your payment provider or business operations.
