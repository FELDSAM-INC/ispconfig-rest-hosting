#!/bin/bash
set -euo pipefail
engine=${1:?Select apache or nginx}
mkdir -p /etc/ispconfig-waf /var/log/ispconfig-waf /var/lib/ispconfig-rest-waf-tmp /var/lib/ispconfig-rest-waf-data /tmp/waf-www
chmod 700 /var/log/ispconfig-waf
chown www-data:www-data /var/lib/ispconfig-rest-waf-{tmp,data}
printf 'fixture\n' > /tmp/waf-www/index.html
cp /tmp/waf-www/index.html /tmp/waf-www/allowed
cp /tmp/waf-www/index.html /tmp/waf-www/other
# Disposable container only: systemd is absent. Actual daemons are started below.
printf '#!/bin/sh\nexit 0\n' > /usr/bin/systemctl
chmod 755 /usr/bin/systemctl
php /app/waf-server/configure.php install "$engine" /etc/modsecurity
php /app/tests/Integration/waf/check-profiles.php
# Even with no opted-in websites, a malformed new base must fail and restore the prior files.
cp /etc/ispconfig-waf/base.conf /tmp/waf-base-before
mkdir /tmp/waf-invalid-source
cp /etc/modsecurity/{modsecurity.conf-recommended,unicode.mapping} /tmp/waf-invalid-source/
printf '\nInvalidWafDirective test\n' >> /tmp/waf-invalid-source/modsecurity.conf-recommended
if php /app/waf-server/configure.php install "$engine" /tmp/waf-invalid-source; then echo 'Invalid rules accepted'; exit 1; fi
cmp /tmp/waf-base-before /etc/ispconfig-waf/base.conf
echo "PASS $engine invalid configuration rejected and restored"
printf '\nListen 127.0.0.1:8080\n' >> /etc/apache2/ports.conf
rm -f /etc/nginx/sites-enabled/default
php /app/tests/Integration/waf/probe.php detection
if [[ "$engine" = apache ]]; then apache2ctl start; port=8080; else nginx; port=8081; fi
request() { curl -s -o /dev/null -w '%{http_code}' -H 'Host: waf.test' "http://127.0.0.1:$port$1"; }
for mode in detection enforcing exclude allowip off; do
    php /app/tests/Integration/waf/probe.php "$mode"
    if [[ "$engine" = apache ]]; then apache2ctl -t; apache2ctl graceful; else nginx -t; nginx -s reload; fi
    sleep .5
    [[ $(request /index.html) = 200 ]]
    expected=200
    [[ "$mode" != enforcing ]] || expected=403
    result=$(request '/allowed?q=1%27%20OR%201%3D1--&password=SECRET_VALUE')
    [[ "$result" = "$expected" ]] || { echo "$engine $mode expected $expected got $result"; exit 1; }
    if [[ "$mode" = exclude ]]; then
        [[ $(request '/other?q=1%27%20OR%201%3D1--') = 403 ]]
        [[ $(request '/allowed?different=1%27%20OR%201%3D1--') = 403 ]]
    fi
    [[ $(curl -s -o /dev/null -w '%{http_code}' -H 'Host: other.test' "http://127.0.0.1:$port/allowed?q=1%27%20OR%201%3D1--") = 403 ]]
    echo "PASS $engine $mode, benign traffic and scoped exceptions"
done
sleep .2
php /app/tests/Integration/waf/check-audit.php "$engine"
# Apache: the findings above are in the JSON audit logs only, not in the web server error log customers read.
if [[ "$engine" = apache ]]; then
    if grep -E 'ModSecurity: (Warning|Access denied)' /var/log/apache2/error.log; then echo 'apache WAF findings in the error log'; exit 1; fi
    echo 'PASS apache WAF findings only in the JSON audit log, not in the error log'
fi

if [[ "$engine" = nginx ]]; then [[ -s /tmp/waf-original-error.log ]]; echo 'PASS nginx preserves original website error log'; fi

# A path prefix ("/section/*") covers the pages below it, only for the selected argument, and not paths that the web
# server resolves elsewhere through dot segments, encoded dots or repeated slashes.
mkdir -p /tmp/waf-www/section/deep
cp /tmp/waf-www/index.html /tmp/waf-www/section/page
cp /tmp/waf-www/index.html /tmp/waf-www/section/index.html
cp /tmp/waf-www/index.html /tmp/waf-www/section/deep/page
cp /tmp/waf-www/index.html /tmp/waf-www/sectionx
php /app/tests/Integration/waf/probe.php prefix
if [[ "$engine" = apache ]]; then apache2ctl -t; apache2ctl graceful; else nginx -t; nginx -s reload; fi
sleep .5
raw() { curl -s --path-as-is -o /dev/null -w '%{http_code}' -H 'Host: waf.test' "http://127.0.0.1:$port$1"; }
attack='q=1%27%20OR%201%3D1--'
for path in /section/page /section/deep/page /section/; do
    actual=$(request "$path?$attack")
    [[ "$actual" = 200 ]] || { echo "$engine prefix $path expected 200 got $actual"; exit 1; }
done
for path in /sectionx /other /section/../other /section/deep/../../other /section/%2e%2e/other /section/%2E%2E/other \
    /section//../other /section/./../other; do
    # The web server serves these paths (no WAF finding), so the 403 below comes from the rule, not from routing.
    [[ $(raw "$path") = 200 ]] || { echo "$engine prefix $path is not served"; exit 1; }
    actual=$(raw "$path?$attack")
    [[ "$actual" = 403 ]] || { echo "$engine prefix $path expected 403 got $actual"; exit 1; }
done
[[ $(request '/section/page?different=1%27%20OR%201%3D1--') = 403 ]]
[[ $(curl -s -o /dev/null -w '%{http_code}' -H 'Host: other.test' "http://127.0.0.1:$port/section/page?$attack") = 403 ]]
echo "PASS $engine path prefix exception: pages below it only, dot segments and encodings resolved"

# Official WordPress Gutenberg exemption must affect only content at its known path.
mkdir -p /tmp/waf-www/wp-json/wp/v2
cp /tmp/waf-www/index.html /tmp/waf-www/wp-json/wp/v2/posts
# Even an administrator's global WordPress default must not override a site's None.
printf '\nSecAction "id:900999,phase:1,pass,nolog,setvar:tx.wordpress-rule-exclusions-plugin_enabled=1"\n' >> /etc/ispconfig-waf/crs-setup.local.conf
for profile in wordpress drupal nextcloud dokuwiki cpanel xenforo none; do
    php /app/tests/Integration/waf/probe.php "$profile"
    if [[ "$engine" = apache ]]; then apache2ctl -t; apache2ctl graceful; else nginx -t; nginx -s reload; fi
    sleep .5
    payload='content=%3Cscript%3Ealert(1)%3C%2Fscript%3E'
    expected=403
    [[ "$profile" != wordpress ]] || expected=200
    actual=$(request "/wp-json/wp/v2/posts?$payload")
    [[ "$actual" = "$expected" ]] || { echo "$engine $profile profile expected $expected got $actual"; exit 1; }
    [[ $(request "/other?$payload") = 403 ]]
    [[ $(request '/wp-json/wp/v2/posts?other=%3Cscript%3Ealert(1)%3C%2Fscript%3E') = 403 ]]
    [[ $(curl -s -o /dev/null -w '%{http_code}' -H 'Host: other.test' "http://127.0.0.1:$port/wp-json/wp/v2/posts?$payload") = 403 ]]
    # Embedding a link in the editor: excluded only on the plugin's main branch after its 1.2.0 tag (pinned by commit).
    embed=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: waf.test' --data 'action=parse-embed&shortcode=[embed]https://example.com/[/embed]' "http://127.0.0.1:$port/wp-admin/admin-ajax.php")
    if [[ "$profile" = wordpress ]]; then [[ "$embed" != 403 ]]; else [[ "$embed" = 403 ]]; fi || { echo "$engine $profile profile: WordPress embed got $embed"; exit 1; }
    echo "PASS $engine application profile $profile: scoped path/argument, other website protected"
done

# Response analysis of a page with "warning" before a long minified line (inline JS/JSON of shop themes) must stay
# within the PCRE match limit: CRS 951190 "Warning.*ingres_" backtracks over the whole line. ModSecurity 2 (Apache)
# exceeded the reference limit of 100000; libmodsecurity 3 (nginx) stays within it either way.
php /app/tests/Integration/waf/probe.php enforcing
if [[ "$engine" = apache ]]; then apache2ctl -t; apache2ctl graceful; errors=/var/log/apache2/error.log; else nginx -t; nginx -s reload; errors=/var/log/nginx/error.log; fi
sleep .5
{ printf '<div class="has-warning">'; head -c 300000 /dev/zero | tr '\0' a; printf '</div>\n'; } > /tmp/waf-www/long.html
[[ $(request /long.html) = 200 ]]
sleep .2
# ModSecurity 2 records execution errors as audit messages too, also when its error-log copy is not written (Apache).
if grep -qi 'limits exceeded' "$errors" /var/log/ispconfig-waf/*.json; then grep -hi 'limits exceeded' "$errors" /var/log/ispconfig-waf/*.json | tail -n 3; echo "$engine PCRE match limit exceeded"; exit 1; fi
echo "PASS $engine long response lines within the PCRE match limit"
