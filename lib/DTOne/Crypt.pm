package DTOne::Crypt;

use strict;
use 5.008_005;
our $VERSION = '0.01';

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(encrypt_aes256gcm decrypt_aes256gcm);

use Crypt::AuthEnc::GCM qw(gcm_encrypt_authenticate gcm_decrypt_verify);
use Crypt::ScryptKDF qw(scrypt_raw);
use Bytes::Random::Secure qw(random_bytes);
use MIME::Base64;

use constant SCRYPT_ITERATIONS      => 2**14;
use constant SCRYPT_BLOCK_SIZE      => 8;
use constant SCRYPT_PARALLELISM     => 1;
use constant SCRYPT_DERIVED_KEY_LEN => 32;

sub encrypt_aes256gcm {
    my ($plaintext, $master_key) = @_;

    my $iv   = random_bytes(12);
    my $salt = random_bytes(16);
    my $key  = scrypt_raw(
        $master_key,
        $salt,
        SCRYPT_ITERATIONS,
        SCRYPT_BLOCK_SIZE,
        SCRYPT_PARALLELISM,
        SCRYPT_DERIVED_KEY_LEN
    );

    my ($ciphertext, $tag) = gcm_encrypt_authenticate(
        'AES',
        $key,
        $iv,
        undef,
        $plaintext
    );

    return encode_base64(join('', $salt, $iv, $tag, $ciphertext), '');
}

sub decrypt_aes256gcm {
    my ($msg, $master_key) = @_;

    $msg = decode_base64($msg);

    my $salt       = substr($msg, 0, 16);
    my $iv         = substr($msg, 16, 12);
    my $tag        = substr($msg, 28, 16);
    my $ciphertext = substr($msg, 44);
    my $key        = scrypt_raw(
        $master_key,
        $salt,
        SCRYPT_ITERATIONS,
        SCRYPT_BLOCK_SIZE,
        SCRYPT_PARALLELISM,
        SCRYPT_DERIVED_KEY_LEN
    );

    return gcm_decrypt_verify(
        'AES',
        $key,
        $iv,
        undef,
        $ciphertext,
        $tag
    );
}

1;
__END__

=encoding utf-8

=head1 NAME

DTOne::Crypt - Cryptographic Toolkit

=head1 SYNOPSIS

  use DTOne::Crypt qw(encrypt_aes256gcm decrypt_aes256gcm);

  my $encrypted = encrypt_aes256gcm($plaintext, $master_key);
  my $decrypted = decrypt_aes256gcm($encrypted, $master_key);

=head1 DESCRIPTION

L<DTOne::Crypt> provides a cryptographic toolkit intended to abstract
complexities in data interchange.

=head1 FUNCTIONS

L<DTone::Crypt> implements the following functions, which can be imported
individually:

=head2 encrypt_aes256gcm

  my $encrypted = encrypt_aes256gcm($plaintext, $master_key);

Encrypt plaintext value using AES-256 GCM to a base64 encoded string containing
the salt, initialization vector (IV), ciphertext, and tag.

=head2 decrypt_aes256gcm

  my $decrypted = decrypt_aes256gcm($encrypted, $master_key);

Decrypt a composite base64 encoded string containing the salt, IV, ciphertext,
and tag back to its original plaintext value.

=head1 AUTHOR

Arnold Tan Casis E<lt>atancasis@cpan.orgE<gt>

=head1 COPYRIGHT

Copyright 2020- Arnold Tan Casis

=head1 LICENSE

This library is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

=head1 SEE ALSO

See L<CryptX> for an excellent generic cryptographic toolkit.

=cut
