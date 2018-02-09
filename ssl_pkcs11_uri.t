#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for http ssl module, loading "engine:pkcs11:" keys.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

plan(skip_all => 'win32') if $^O eq 'MSWin32';

plan(skip_all => 'may not work, leaves coredump')
	unless $ENV{TEST_NGINX_UNSAFE};

my $t = Test::Nginx->new()->has(qw/http proxy http_ssl/)->has_daemon('openssl')
	->has_daemon('softhsm2-util')->has_daemon('pkcs11-tool')->plan(1);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8081 ssl;
        listen       127.0.0.1:8080;
        server_name  localhost;

        ssl_certificate_key "engine:pkcs11:pkcs11:token=NginxZero;object=nx_key_0;type=private;pin-value=1234";
        ssl_certificate localhost.crt;

        location / {
            # index index.html by default
        }
        location /proxy {
            proxy_pass https://127.0.0.1:8081/;
        }
    }
}

EOF

# Create a OpenSSL configuration file
my $module_path = `find /usr -name *libsofthsm*.so 2>/dev/null | head -n 1 | \
    tr -d "\n"`;
my $dynamic_path = `find /usr -name *pkcs11*.so 2>/dev/null | grep engine | \
    head -n 1 | tr -d "\n"`;

$t->write_file('openssl.conf', <<EOF);
openssl_conf = openssl_def

[openssl_def]
engines = engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = $dynamic_path
MODULE_PATH = $module_path
init = 0

[ req ]
default_bits = 1024
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $d = $t->testdir();

# Test if OpenSSL is already configured with the engine pkcs11
# If not, create a local configuration
my $openssl_config;
eval "openssl engine -t pkcs11";
if ($? == 0) {
    $openssl_config = "";
} else {
    $openssl_config = "-config $d/openssl.conf";
}

# Configure SoftHSM to create a local database for the keys
$t->write_file('softhsm.conf', <<EOF);
objectstore.backend = file
directories.tokendir = $d/softhsm.db
EOF

$ENV{SOFTHSM2_CONF} = "$d/softhsm.conf";
$ENV{PKCS11_MODULE_PATH} = "$module_path";
mkdir("$d/softhsm.db");

# Create a new SoftHSM device, generate a key pair and a self-signed
# certificate
foreach my $name ('localhost') {
	system('softhsm2-util --init-token --free --label "NginxZero" '
		. '--pin 1234 --so-pin 1234 '
		. ">>$d/openssl.out 2>&1") == 0
        or exit($?);

	system('pkcs11-tool --module='
        . "$module_path -p 1234 -l -k -d 0 -a nx_key_0 --key-type rsa:1024 "
		. ">>$d/openssl.out 2>&1") == 0
        or exit($?);

	system('openssl req -x509 -new -engine pkcs11 '
		. "$openssl_config -subj \"/CN=$name\" "
		. "-out $d/$name.crt -keyform engine "
        . '-key "pkcs11:token=NginxZero;object=nx_key_0;type=private'
        . ';pin-value=1234" '
		. ">>$d/openssl.out 2>&1") == 0
		or exit($?);
}

$t->run();

$t->write_file('index.html', '');

###############################################################################

like(http_get('/proxy', socket => get_ssl_socket()), qr/200 OK/, 'https');

###############################################################################
#
sub get_ssl_socket {
	my $s;

	eval {
		local $SIG{ALRM} = sub { die "timeout\n" };
		local $SIG{PIPE} = sub { die "sigpipe\n" };
		alarm(2);
		$s = IO::Socket::SSL->new(
			Proto => 'tcp',
			PeerAddr => 'localhost:',
            PeerPort => 8081,
			SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
			SSL_error_trap => sub { die $_[1] }
		);
		alarm(0);
	};
	alarm(0);

	if ($@) {
		log_in("died: $@");
		return undef;
	}

	return $s;
}

###############################################################################
