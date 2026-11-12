# Spark push relay

Delivers a Spark server's push notifications to phones and TVs:

- **Spark apps** on iPhone, iPad, Apple TV and Mac through APNs, with the
  `.p8` key of the Apple Developer account that signs them;
- **Spark app** on Android through Firebase Cloud Messaging;
- optionally the **official Silo apps**: with `FORWARD_RELAY_URL` set, their
  Apple pushes go on to the official Silo relay, where this relay registers as
  one deployment. Off by default; Spark servers accept only the Spark apps.

It speaks the relay protocol Silo servers already use, so a Spark server needs
no changes: it registers on first push (`/v1/deployments/register`), renews
its signed capability before it expires, and sends one `private_alert` per
push. A push carries only the delivery ID (plus the server and profile it is
for); the app fetches the real text from its own server, and shows
`ALERT_TITLE` / `ALERT_BODY` when it cannot.

State (registered deployments, a day of idempotency records, the forwarding
credential) is one JSON file in `/data`.

## Run

```sh
mkdir -p /mnt/user/appdata/spark-relay/{data,secrets}
chown -R 99:100 /mnt/user/appdata/spark-relay
cp relay.env.example relay.env   # fill in CAPABILITY_SECRET, keys if you have them
docker compose up -d
curl http://localhost:9099/healthz   # ok
```

Without an APNs key or Firebase account the relay still runs and answers
Spark-app pushes with a clear error.

## Pangolin

The Spark server only accepts `https://push.atlaslab.uk` as its relay, so
Pangolin must publish the relay there, over HTTPS, without Pangolin's login
in front (servers call it, not people).
