- If upstream peer is http but trying to connect as https throw better error
- Config for upstream server with self signed cert
  peer.options.verify_cert = false;
  peer.options.verify_hostname = false;
- (Partial) Add correct response for peer not found/peer down
- Redirect scheme type auto
- RateLimit using pingora-limit [https://github.com/cloudflare/pingora/blob/main/docs/user_guide/rate_limiter.md]
- Pingora Config [https://github.com/cloudflare/pingora/blob/main/docs/user_guide/conf.md]
