# DNS

Look up a name with DNS over HTTPS. The query goes straight to the provider you pick.

Open `index.html` in a browser, or serve this directory with any static file server. There is no build step.

## Lookup

The default type asks for A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, CAA, and HTTPS, then merges the answers. An IP address, or a reverse name, is looked up as PTR instead.

Other types are queried on their own. Providers are Cloudflare, Quad9, Google, and a custom HTTPS resolver. A custom resolver has to answer a simple GET with `Access-Control-Allow-Origin`.

DNSSEC is checked in the browser against the IANA root trust anchors. Uncheck **Disable DNSSEC verification** to turn that off. The resolver's AD bit is not used for that check.

## Link

A link stores the name, and the type when it is not the default. Provider, custom URL, and the settings below stay in the browser.

**Auto update URL** is off. The address changes when you look something up. Turn it on to rewrite the address as you edit the form.

## Settings

- **Show WHOIS** reads registration data from RDAP.
- **Link domains and IP addresses** turns names and addresses in the answer into lookups. An address link uses the default type, which looks the address up as PTR.
- **Show ipinfo.io for IP addresses** loads ipinfo.io for an address or reverse name and shows the parsed response. The heading links to the ipinfo.io page.

An address the IANA special-purpose registries mark as not globally reachable, and IPv4 or IPv6 multicast, is not sent to RDAP or ipinfo.io. The result names that reservation and links the RFC. A globally reachable allocation inside one of those blocks is looked up as usual.
