-module(i2p_keys).

-moduledoc """
Standard I2P identities: the `KeysAndCert` structure shared by RouterIdentity
and Destination (identical on the wire).

An identity is a fixed 384-byte region of keys and padding followed by a
Certificate:

- the crypto (encryption) public key, left-justified at offset 0;
- the signing public key, right-justified at the end of the 384 bytes;
- random padding in between, sized so
  `public_key length + padding length + signing_key length == 384` (Proposal
  161, <https://i2p.net/en/spec/proposals/161-padding-compression>). For a
  compressed RouterIdentity the padding is the same 32-byte block repeated,
  so it can be stored as a single block plus a count;
- the certificate, immediately after the 384 bytes.

For the ECIES-X25519 / Ed25519 identity (sig type 7, crypto type 4) this is
`X25519 pub (32) ‖ padding (320) ‖ Ed25519 pub (32) ‖ KEY(5) cert (7)` = 391
bytes total. The identity hash is the SHA-256 of the full 391 bytes.

The Base64 form is the identity bytes encoded with the I2P alphabet
(`A-Za-z0-9-~`) and `=` padding, as used in RouterInfo and `hosts.txt`; the
Base32 form is the lower-case, padding-free Base32 (RFC 4648) of the identity
hash plus the `.b32.i2p` suffix, used as a Destination address.

Only the X25519 + Ed25519 key types are supported; identities with other key
types are recognized but rejected with a descriptive reason.

## Usage

```erlang
%% Generate a fresh RouterIdentity / Destination
Identity = i2p_keys:generate_identity(),
391 = byte_size(i2p_keys:to_binary(Identity)),
Hash = i2p_keys:hash(Identity),                    %% SHA-256, 32 bytes
B64 = i2p_keys:to_b64(Identity),                   %% 524 chars, I2P alphabet
Addr = i2p_keys:to_b32(Identity),                  %% 52 chars + ".b32.i2p"
{ok, Identity} = i2p_keys:from_b64(B64),           %% round-trip
Pub = i2p_keys:public_key(Identity),               %% X25519, 32 bytes
SPub = i2p_keys:signing_key(Identity),             %% Ed25519, 32 bytes
```

## Validation

The wire layout, Base64 and Base32 encodings are validated against the
reference i2p-java and i2pd implementations.
""".

-export([
    generate_identity/0,
    generate_with_privkeys/0,
    dest_blob/1,
    parse_dest_blob/1,
    from_keys/2,
    parse/1,
    to_binary/1,
    hash/1,
    public_key/1,
    signing_key/1,
    padding/1,
    cert/1,
    cert_type/1,
    sig_type/1,
    crypt_type/1,
    to_b64/1,
    from_b64/1,
    encode_b64/1,
    decode_b64/1,
    to_b32/1,
    encode_b32/1
]).

-export_type([identity/0]).

-doc """
A parsed standard identity: the full wire bytes plus the extracted fields.

Only the X25519 + Ed25519 key types (`sig_type` 7, `crypt_type` 4) are
represented; other key types are rejected by `parse/1`.
""".
-opaque identity() :: #{
    binary := binary(),
    crypto_key := i2p_crypto:x25519_public_key(),
    signing_key := i2p_crypto:ed25519_public_key(),
    padding := binary(),
    cert := binary(),
    cert_type := byte(),
    sig_type := non_neg_integer(),
    crypt_type := non_neg_integer()
}.

-define(KEYS_REGION_SIZE, 384).
-define(PADDING_BLOCKS, 10).
-define(PAD_COMP_LEN, 32).
-define(CERT_TYPE_NULL, 0).
-define(CERT_TYPE_KEY, 5).
-define(SIG_TYPE_ED25519, 7).
-define(CRYPT_TYPE_X25519, 4).
-define(B64_ALPHABET, <<"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~">>).
-define(B32_ALPHABET, <<"abcdefghijklmnopqrstuvwxyz234567">>).

-doc """
Generate a fresh X25519 + Ed25519 identity (RouterIdentity or Destination).

Input: none.
Output: a new `identity()` with a random 32-byte padding block repeated 10
times (compressible per Proposal 161) and a KEY(5) certificate
(`sig_type` 7, `crypt_type` 4). The private keys are discarded; callers that
need them should generate key pairs with `m:i2p_crypto` and pass the public
keys to `from_keys/2`.
""".
-spec generate_identity() -> identity().
generate_identity() ->
    {CPub, _CPriv} = i2p_crypto:x25519_keygen(),
    {SPub, _SPriv} = i2p_crypto:ed25519_keygen(),
    from_keys(CPub, SPub).

-doc """
Generate a fresh identity and return both public and private key material.

Like `generate_identity/0` but retains the private keys. Used by the SAM
bridge for `DEST GENERATE`: the returned map carries the `identity()`
(`Destination`) and the two 32-byte private keys that correspond to the
X25519 and Ed25519 public keys embedded in the identity.

Output: a map with keys `identity`, `crypto_priv`, `sign_priv`.
""".
-spec generate_with_privkeys() ->
    #{identity := identity(), crypto_priv := binary(), sign_priv := binary()}.
generate_with_privkeys() ->
    {CPub, CPriv} = i2p_crypto:x25519_keygen(),
    {SPub, SPriv} = i2p_crypto:ed25519_keygen(),
    #{identity => from_keys(CPub, SPub), crypto_priv => CPriv, sign_priv => SPriv}.

-doc """
Encode a SAM destination blob: `Destination ‖ CryptoPrivateKey ‖ SigningPrivateKey`.

This is the binary form returned by `DEST GENERATE` and accepted by
`SESSION CREATE`. Callers encode the result with `f:encode_b64/1` before
sending it on the wire.

Input: `Map` — a map with `identity`, `crypto_priv`, `sign_priv` (as returned
by `f:generate_with_privkeys/0`).
Output: the concatenated binary (455 bytes for Ed25519).
""".
-spec dest_blob(#{identity := identity(), crypto_priv := binary(), sign_priv := binary()}) ->
    binary().
dest_blob(#{identity := #{binary := Dest}, crypto_priv := CPriv, sign_priv := SPriv}) ->
    <<Dest/binary, CPriv/binary, SPriv/binary>>.

-doc """
Parse a SAM destination blob back into its components.

Input: `Blob` — the raw binary `Destination ‖ CryptoPrivateKey ‖ SigningPrivateKey`
(455 bytes for Ed25519).
Output: `{ok, Map}` with `identity`, `crypto_priv`, `sign_priv`, or
`{error, Reason}` on malformed input.
""".
-spec parse_dest_blob(binary()) ->
    {ok, #{identity := identity(), crypto_priv := binary(), sign_priv := binary()}}
    | {error, term()}.
parse_dest_blob(<<DestBin:?KEYS_REGION_SIZE/binary, CertAndKeys/binary>>) ->
    CertLen = cert_wire_length(CertAndKeys),
    %% Stays a case: the IdentityTail segment size is CertLen, computed above —
    %% a head pattern cannot reference bindings from outside itself.
    case CertAndKeys of
        <<IdentityTail:CertLen/binary, CPriv:32/binary, SPriv:32/binary>> ->
            IdentityBin = <<DestBin/binary, IdentityTail/binary>>,
            case parse(IdentityBin) of
                {ok, Id} ->
                    {ok, #{identity => Id, crypto_priv => CPriv, sign_priv => SPriv}};
                {error, _} = Err ->
                    Err
            end;
        _ ->
            {error, bad_dest_blob}
    end;
parse_dest_blob(_) ->
    {error, bad_dest_blob}.

cert_wire_length(<<?CERT_TYPE_KEY, Len:16/big, _/binary>>) ->
    3 + Len;
cert_wire_length(<<?CERT_TYPE_NULL, 0, 0>>) ->
    3;
cert_wire_length(<<?CERT_TYPE_NULL, Len:16/big, _/binary>>) ->
    3 + Len;
cert_wire_length(_) ->
    0.

-doc """
Build an identity from explicit X25519 and Ed25519 public keys.

Input: `CryptoPub` — the 32-byte X25519 public key; `SigningPub` — the
32-byte Ed25519 public key.
Output: an `identity()` with a fresh random padding block and the standard
KEY(5) certificate.
""".
-spec from_keys(i2p_crypto:x25519_public_key(), i2p_crypto:ed25519_public_key()) -> identity().
from_keys(CryptoPub, SigningPub) when
    byte_size(CryptoPub) =:= 32, byte_size(SigningPub) =:= 32
->
    Block = crypto:strong_rand_bytes(?PAD_COMP_LEN),
    Padding = binary:copy(Block, ?PADDING_BLOCKS),
    Cert = <<?CERT_TYPE_KEY, 0, 4, 0, ?SIG_TYPE_ED25519, 0, ?CRYPT_TYPE_X25519>>,
    build_map(CryptoPub, Padding, SigningPub, Cert).

-doc """
Parse and validate a standard identity from its wire bytes.

Input: `Bin` — the identity bytes (`keys + padding + certificate`).
Output: `{ok, identity()}` for a well-formed X25519 + Ed25519 identity with a
NULL or KEY certificate; `{error, Reason}` otherwise. Reasons: `too_short`,
`badarg`, `{bad_cert_length, N}`, `{unknown_cert_type, N}`,
`{unsupported_identity, {SigType, CryptType}}` (recognized key types outside
X25519 + Ed25519, including the ElGamal + DSA pair implied by a NULL
certificate), or `{unsupported_identity, short_key_cert}` for a KEY
certificate shorter than 4 bytes.
""".
-spec parse(binary()) -> {ok, identity()} | {error, term()}.
parse(Bin) when is_binary(Bin) ->
    Size = byte_size(Bin),
    case Size < ?KEYS_REGION_SIZE + 3 of
        true ->
            {error, too_short};
        false ->
            <<KeysRegion:?KEYS_REGION_SIZE/binary, Cert/binary>> = Bin,
            parse_cert(KeysRegion, Cert)
    end;
parse(_) ->
    {error, badarg}.

-doc """
Return the full wire bytes of the identity (keys + padding + certificate).
""".
-spec to_binary(identity()) -> binary().
to_binary(#{binary := Bin}) ->
    Bin.

-doc """
Return the identity hash: SHA-256 of the full wire bytes (32 bytes).
""".
-spec hash(identity()) -> i2p_crypto:hash().
hash(#{binary := Bin}) ->
    crypto:hash(sha256, Bin).

-doc """
Return the X25519 encryption public key (32 bytes, crypto type 4).
""".
-spec public_key(identity()) -> i2p_crypto:x25519_public_key().
public_key(#{crypto_key := Pub}) ->
    Pub.

-doc """
Return the Ed25519 signing public key (32 bytes, sig type 7).
""".
-spec signing_key(identity()) -> i2p_crypto:ed25519_public_key().
signing_key(#{signing_key := Pub}) ->
    Pub.

-doc """
Return the padding bytes between the two keys (320 bytes for this key type).
""".
-spec padding(identity()) -> binary().
padding(#{padding := Padding}) ->
    Padding.

-doc """
Return the certificate bytes as they appear on the wire (7 bytes for KEY(5)).
""".
-spec cert(identity()) -> binary().
cert(#{cert := Cert}) ->
    Cert.

-doc """
Return the certificate type byte: 0 (NULL) or 5 (KEY).
""".
-spec cert_type(identity()) -> byte().
cert_type(#{cert_type := Type}) ->
    Type.

-doc """
Return the signing key type from the KEY certificate (7 = Ed25519).
""".
-spec sig_type(identity()) -> non_neg_integer().
sig_type(#{sig_type := Type}) ->
    Type.

-doc """
Return the crypto key type from the KEY certificate (4 = X25519).
""".
-spec crypt_type(identity()) -> non_neg_integer().
crypt_type(#{crypt_type := Type}) ->
    Type.

-doc """
Return the identity Base64: the wire bytes with the I2P alphabet
(`A-Za-z0-9-~`) and `=` padding.
""".
-spec to_b64(identity()) -> binary().
to_b64(#{binary := Bin}) ->
    encode_b64(Bin).

-doc """
Parse an identity from its Base64 form (I2P alphabet, `=` padding optional).

Input: `B64` — the Base64 string, as used in RouterInfo and `hosts.txt`.
Output: `{ok, identity()}` on success, `{error, Reason}` otherwise (see
`parse/1`; a malformed Base64 string yields `{error, badarg}`).
""".
-spec from_b64(binary() | string()) -> {ok, identity()} | {error, term()}.
from_b64(B64) ->
    try decode_b64(B64) of
        Bin -> parse(Bin)
    catch
        error:badarg -> {error, badarg}
    end.

-doc """
Encode bytes with the I2P Base64 alphabet (`A-Za-z0-9-~`), `=` padding added.

Input: `Data` — any binary.
Output: the Base64 string as a binary.
""".
-spec encode_b64(binary()) -> binary().
encode_b64(Bin) when is_binary(Bin) ->
    encode_b64(Bin, []);
encode_b64(_) ->
    error(badarg).

-doc """
Decode an I2P Base64 string (alphabet `A-Za-z0-9-~`), padding optional.

Input: `B64` — the Base64 string, either a binary or a character list.
Output: the decoded bytes. Raises `error(badarg)` on a malformed string
(wrong length, or a character outside the alphabet).
""".
-spec decode_b64(binary() | string()) -> binary().
decode_b64(B64) when is_binary(B64) ->
    decode_b64_rem(strip_b64_padding(B64), []);
decode_b64(B64) when is_list(B64) ->
    decode_b64(list_to_binary(B64));
decode_b64(_) ->
    error(badarg).

-doc """
Return the Destination address: lower-case, padding-free Base32 (RFC 4648)
of the identity hash plus `.b32.i2p` (52 chars + suffix, 60 bytes total).
""".
-spec to_b32(identity()) -> <<_:480>>.
to_b32(Identity) ->
    <<(encode_b32(hash(Identity)))/binary, ".b32.i2p">>.

-doc """
Encode bytes with the lower-case, padding-free Base32 alphabet (RFC 4648).

This is the form used by Destination addresses: the identity hash (32
bytes) encodes to 52 characters, to which `.b32.i2p` is appended by
`to_b32/1`.

Input: `Data` — any binary.
Output: the Base32 string as a binary.
""".
-spec encode_b32(binary()) -> binary().
encode_b32(Bin) when is_binary(Bin) ->
    encode_b32(Bin, []).

%%%%%%% %%% Internal %%%%%%%

parse_cert(KeysRegion, Cert = <<?CERT_TYPE_KEY, Len:16/big, Payload/binary>>) ->
    %% Stays a case: the scrutinee is compound ({byte_size(Payload), Len}) and
    %% the {_Size, Len} arm re-matches head-bound Len as an equality test —
    %% neither can become head clauses.
    case {byte_size(Payload), Len} of
        {Size, Size} when Size >= 4 ->
            <<Sig:16/big, Crypt:16/big, Extra/binary>> = Payload,
            case {Sig, Crypt, Extra} of
                {?SIG_TYPE_ED25519, ?CRYPT_TYPE_X25519, <<>>} ->
                    {ok, extract_x25519_ed25519(KeysRegion, Cert)};
                {OtherSig, OtherCrypt, _Extra} ->
                    {error, {unsupported_identity, {OtherSig, OtherCrypt}}}
            end;
        {Size, Size} ->
            {error, {unsupported_identity, short_key_cert}};
        {_Size, Len} ->
            {error, {bad_cert_length, Len}}
    end;
parse_cert(_KeysRegion, <<?CERT_TYPE_NULL, 0, 0>>) ->
    {error, {unsupported_identity, {0, 0}}};
parse_cert(_KeysRegion, <<?CERT_TYPE_NULL, Len:16/big, _/binary>>) ->
    {error, {bad_cert_length, Len}};
parse_cert(_KeysRegion, <<Type, _/binary>>) ->
    {error, {unknown_cert_type, Type}}.

extract_x25519_ed25519(<<CryptoPub:32/binary, Padding:320/binary, SigningPub:32/binary>>, Cert) ->
    build_map(CryptoPub, Padding, SigningPub, Cert).

build_map(CryptoPub, Padding, SigningPub, Cert) ->
    <<CertType, _Len:16/big, Payload/binary>> = Cert,
    <<Sig:16/big, Crypt:16/big>> = Payload,
    #{
        binary => <<CryptoPub/binary, Padding/binary, SigningPub/binary, Cert/binary>>,
        crypto_key => CryptoPub,
        signing_key => SigningPub,
        padding => Padding,
        cert => Cert,
        cert_type => CertType,
        sig_type => Sig,
        crypt_type => Crypt
    }.

strip_b64_padding(Bin) ->
    strip_b64_padding(Bin, 0).

strip_b64_padding(Bin, Count) ->
    Size = byte_size(Bin),
    case Size > Count andalso binary:at(Bin, Size - Count - 1) =:= $= of
        true -> strip_b64_padding(Bin, Count + 1);
        false -> binary:part(Bin, 0, Size - Count)
    end.

encode_b64(<<B1, B2, B3, Rest/binary>>, Acc) ->
    <<C1:6, C2:6, C3:6, C4:6>> = <<B1, B2, B3>>,
    encode_b64(Rest, [<<(b64char(C1)), (b64char(C2)), (b64char(C3)), (b64char(C4))>> | Acc]);
encode_b64(<<B1, B2>>, Acc) ->
    <<C1:6, C2:6, C3:6>> = <<B1, B2, 0:2>>,
    finish_b64_enc(Acc, <<(b64char(C1)), (b64char(C2)), (b64char(C3)), $=>>);
encode_b64(<<B1>>, Acc) ->
    <<C1:6, C2:6>> = <<B1, 0:4>>,
    finish_b64_enc(Acc, <<(b64char(C1)), (b64char(C2)), $=, $=>>);
encode_b64(<<>>, Acc) ->
    finish_b64_enc(Acc, <<>>).

finish_b64_enc(Acc, Tail) ->
    iolist_to_binary(lists:reverse(Acc, [Tail])).

decode_b64_rem(<<C1, C2, C3, C4, Rest/binary>>, Acc) ->
    <<B1, B2, B3>> = <<(b64val(C1)):6, (b64val(C2)):6, (b64val(C3)):6, (b64val(C4)):6>>,
    decode_b64_rem(Rest, [<<B1, B2, B3>> | Acc]);
decode_b64_rem(<<C1, C2, C3>>, Acc) ->
    <<B1, B2, _:2>> = <<(b64val(C1)):6, (b64val(C2)):6, (b64val(C3)):6>>,
    finish_b64_dec(Acc, [<<B1, B2>>]);
decode_b64_rem(<<C1, C2>>, Acc) ->
    <<B1, _:8>> = <<(b64val(C1)):6, (b64val(C2)):6, 0:4>>,
    finish_b64_dec(Acc, [<<B1>>]);
decode_b64_rem(<<>>, Acc) ->
    finish_b64_dec(Acc, []);
decode_b64_rem(_, _Acc) ->
    error(badarg).

finish_b64_dec(Acc, Tail) ->
    iolist_to_binary(lists:reverse(Acc, Tail)).

b64char(Index) ->
    binary:at(?B64_ALPHABET, Index).

b64val(C) when C >= $A, C =< $Z -> C - $A;
b64val(C) when C >= $a, C =< $z -> C - $a + 26;
b64val(C) when C >= $0, C =< $9 -> C - $0 + 52;
b64val($-) -> 62;
b64val($~) -> 63;
b64val(_) -> error(badarg).

encode_b32(<<B1, B2, B3, B4, B5, Rest/binary>>, Acc) ->
    <<C1:5, C2:5, C3:5, C4:5, C5:5, C6:5, C7:5, C8:5>> = <<B1, B2, B3, B4, B5>>,
    Chars = <<
        (b32char(C1)),
        (b32char(C2)),
        (b32char(C3)),
        (b32char(C4)),
        (b32char(C5)),
        (b32char(C6)),
        (b32char(C7)),
        (b32char(C8))
    >>,
    encode_b32(Rest, [Chars | Acc]);
encode_b32(<<B1, B2, B3, B4>>, Acc) ->
    <<C1:5, C2:5, C3:5, C4:5, C5:5, C6:5, C7:5>> = <<B1, B2, B3, B4, 0:3>>,
    tail_b32(Acc, [C1, C2, C3, C4, C5, C6, C7]);
encode_b32(<<B1, B2, B3>>, Acc) ->
    <<C1:5, C2:5, C3:5, C4:5, C5:5>> = <<B1, B2, B3, 0:1>>,
    tail_b32(Acc, [C1, C2, C3, C4, C5]);
encode_b32(<<B1, B2>>, Acc) ->
    <<C1:5, C2:5, C3:5, C4:5>> = <<B1, B2, 0:4>>,
    tail_b32(Acc, [C1, C2, C3, C4]);
encode_b32(<<B1>>, Acc) ->
    <<C1:5, C2:5>> = <<B1, 0:2>>,
    tail_b32(Acc, [C1, C2]);
encode_b32(<<>>, Acc) ->
    tail_b32(Acc, []).

tail_b32(Acc, Chars) ->
    iolist_to_binary(lists:reverse(Acc, [<<(b32char(C))>> || C <- Chars])).

b32char(Index) ->
    binary:at(?B32_ALPHABET, Index).
