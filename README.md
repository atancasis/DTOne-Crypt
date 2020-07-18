# NAME

DTOne::Crypt - Cryptographic Toolkit

# SYNOPSIS

    use DTOne::Crypt qw(encrypt_aes256gcm decrypt_aes256gcm);

    my $encrypted = encrypt_aes256gcm($plaintext, $master_key);
    my $decrypted = decrypt_aes256gcm($encrypted, $master_key);

# DESCRIPTION

[DTOne::Crypt](https://metacpan.org/pod/DTOne%3A%3ACrypt) provides a cryptographic toolkit intended to abstract
complexities in data interchange.

# FUNCTIONS

[DTone::Crypt](https://metacpan.org/pod/DTone%3A%3ACrypt) implements the following functions, which can be imported
individually:

## encrypt\_aes256gcm

    my $encrypted = encrypt_aes256gcm($plaintext, $master_key);

Encrypt plaintext value using AES-256 GCM to a base64 encoded string containing
the salt, initialization vector (IV), ciphertext, and tag.

## decrypt\_aes256gcm

    my $decrypted = decrypt_aes256gcm($encrypted, $master_key);

Decrypt a composite base64 encoded string containing the salt, IV, ciphertext,
and tag back to its original plaintext value.

# AUTHOR

Arnold Tan Casis <atancasis@cpan.org>

# COPYRIGHT

Copyright 2020- Arnold Tan Casis

# LICENSE

This library is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

# SEE ALSO

See [CryptX](https://metacpan.org/pod/CryptX) for an excellent generic cryptographic toolkit.
