use strict;
use Test::More;
use DTOne::Crypt qw(encrypt_aes256gcm decrypt_aes256gcm);

my $key       = "YL61pQsgFez6rQnNjRkI0glz6PoXnctdzWcoA3bEfNs=";
my $plaintext = "Lorem Ipsum";

my $encrypted = encrypt_aes256gcm($plaintext, $key);
my $decrypted = decrypt_aes256gcm($encrypted, $key);

is($decrypted, $plaintext, "decrypting message matches original");

done_testing;
