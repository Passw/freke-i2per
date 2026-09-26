-module(i2p_su3).

-moduledoc """
SU3 signed-file container: the envelope I2P uses for reseed data and,
elsewhere in the ecosystem, router updates, plugins and the news feed.

Wire format ([update spec](https://geti2p.net/en/docs/spec/updates)); all
integers big-endian, header exactly 40 bytes:

```
0-5     magic "I2Psu3"
6       unused = 0
7       SU3 format version = 0
8-9     signature type (16#0006 = RSA-SHA512-4096)
10-11   signature length   (512 for type 6)
12      unused = 0
13      version length     (>= 16)
14      unused = 0
15      signer ID length
16-23   content length
24      unused = 0
25      file type          (0 = zip)
26      unused = 0
27      content type       (3 = reseed data)
28-39   unused = 0
40..    version            UTF-8, zero-padded to the declared length
        signer ID          UTF-8
        content
        signature          over bytes 0 .. end-of-content
```

The signature is the raw RSA operation over the SHA-512 digest of the covered
bytes. Trust anchors are local X.509 certificates selected by signer ID; reseed
files carry no certificate of their own. See `m:i2p_reseed`.

Only RSA-SHA512-4096 is implemented: it is the only type live reseeds use.
Decoding is strict — wrong magic or format version, any other signature type,
a version field shorter than 16 bytes, or trailing bytes after the signature
are errors.

## Usage

```erlang
{ok, Su3} = i2p_su3:decode(Bin),
3 = i2p_su3:content_type(Su3),               %% reseed data
0 = i2p_su3:file_type(Su3),                  %% zip payload
ok = i2p_su3:verify(Su3, CertDer),
Content = i2p_su3:content(Su3)               %% zip bytes for f:zip:unzip/2
```
""".

-export([
    decode/1,
    verify/2,
    encode/4,
    version/1,
    signer_id/1,
    file_type/1,
    content_type/1,
    content/1,
    cert_public_key/1,
    cert_valid_at/2
]).
-export_type([su3/0]).

-define(MAGIC, <<"I2Psu3">>).
-define(HEADER_SIZE, 40).
-define(SIG_TYPE_RSA_SHA512_4096, 16#0006).
-define(SIG_LEN_RSA_SHA512_4096, 512).
-define(FILE_TYPE_ZIP, 0).
-define(CONTENT_TYPE_RESEED, 3).

-doc """
A decoded SU3 container.

- `signed` — every byte the signature covers: header ‖ version ‖ signer ID ‖
  content.
- `version` — UTF-8 with trailing zero padding stripped (the padding sits
  inside the signed region; stripping it after decoding is loss-free).
""".
-type su3() :: #{
    signed := binary(),
    version := binary(),
    signer_id := binary(),
    file_type := byte(),
    content_type := byte(),
    content := binary(),
    signature := binary()
}.

-doc """
Build an SU3 file.

Input: `Version` — UTF-8 version string (zero-padded to at least 16 bytes per
spec); `SignerId` — UTF-8 signer identity; `Content` — payload bytes;
`PrivKey` — an RSA-4096 `'RSAPrivateKey'{}` record. File type and content type
are fixed to zip/reseed, the combination used by the router.
Output: the raw SU3 binary, verifiable with `f:verify/2` against the matching
certificate.
""".
-spec encode(binary(), binary(), binary(), public_key:rsa_private_key()) ->
    binary().
encode(Version, SignerId, Content, PrivKey) when byte_size(Version) < 16 ->
    Pad = 16 - byte_size(Version),
    encode(<<Version/binary, 0:Pad/unit:8>>, SignerId, Content, PrivKey);
encode(Version, SignerId, Content, PrivKey) ->
    VLen = byte_size(Version),
    SignerLen = byte_size(SignerId),
    ContentLen = byte_size(Content),
    Signed =
        <<
            ?MAGIC/binary,
            0:8,
            0:8,
            ?SIG_TYPE_RSA_SHA512_4096:16/big,
            ?SIG_LEN_RSA_SHA512_4096:16/big,
            0:8,
            VLen:8,
            0:8,
            SignerLen:8,
            ContentLen:64/big,
            0:8,
            ?FILE_TYPE_ZIP:8,
            0:8,
            ?CONTENT_TYPE_RESEED:8,
            0:96,
            Version/binary,
            SignerId/binary,
            Content/binary
        >>,
    Digest = crypto:hash(sha512, Signed),
    Signature = raw_rsa_sign(Digest, PrivKey),
    <<Signed/binary, Signature/binary>>.

-doc """
Decode an SU3 container.

Input: `Bin` — the raw file bytes.
Output: `{ok, Su3}`, or `{error, Reason}` with `Reason` one of
`truncated_header | bad_magic | bad_format_version | short_version |
{unsupported_signature_type, Type} | bad_signature_length | truncated |
trailing_data`.
""".
-spec decode(binary()) -> {ok, su3()} | {error, term()}.
decode(Bin) when byte_size(Bin) < ?HEADER_SIZE ->
    {error, truncated_header};
decode(Bin) when binary_part(Bin, 0, 6) =/= ?MAGIC ->
    {error, bad_magic};
decode(Bin) ->
    %% Reserved bytes are tolerated whatever their value; every field with
    %% spec meaning is checked by decode_body/9 in declaration order.
    <<
        _:6/binary,
        _:8,
        FormatVer:8,
        SigType:16/big,
        SigLen:16/big,
        _:8,
        VerLen:8,
        _:8,
        SignerLen:8,
        ContentLen:64/big,
        _:8,
        FileType:8,
        _:8,
        ContentType:8,
        _:96,
        _Body/binary
    >> = Bin,
    decode_body(
        Bin, FormatVer, SigType, SigLen, VerLen, SignerLen, ContentLen, FileType, ContentType
    ).

decode_body(_Bin, FormatVer, _SigType, _SigLen, _VerLen, _SignerLen, _ContentLen, _FT, _CT) when
    FormatVer =/= 0
->
    {error, bad_format_version};
decode_body(_Bin, _FormatVer, SigType, _SigLen, _VerLen, _SignerLen, _ContentLen, _FT, _CT) when
    SigType =/= ?SIG_TYPE_RSA_SHA512_4096
->
    {error, {unsupported_signature_type, SigType}};
decode_body(_Bin, _FormatVer, _SigType, SigLen, _VerLen, _SignerLen, _ContentLen, _FT, _CT) when
    SigLen =/= ?SIG_LEN_RSA_SHA512_4096
->
    {error, bad_signature_length};
decode_body(_Bin, _FormatVer, _SigType, _SigLen, VerLen, _SignerLen, _ContentLen, _FT, _CT) when
    VerLen < 16
->
    {error, short_version};
decode_body(
    Bin, _FormatVer, _SigType, SigLen, VerLen, SignerLen, ContentLen, FileType, ContentType
) ->
    Expected = ?HEADER_SIZE + VerLen + SignerLen + ContentLen + SigLen,
    case byte_size(Bin) - Expected of
        0 -> split_body(Bin, VerLen, SignerLen, ContentLen, FileType, ContentType, SigLen);
        Short when Short < 0 -> {error, truncated};
        _Trailing -> {error, trailing_data}
    end.

%% The signature covers the file from byte 0 through end-of-content; the
%% variable fields and that covered prefix are two overlapping views of the
%% same bytes, matched separately.
split_body(Bin, VerLen, SignerLen, ContentLen, FileType, ContentType, SigLen) ->
    <<Signed:(?HEADER_SIZE + VerLen + SignerLen + ContentLen)/binary, Signature:SigLen/binary>> =
        Bin,
    <<_:?HEADER_SIZE/binary, Version0:VerLen/binary, SignerId:SignerLen/binary,
        Content:ContentLen/binary, _Signature/binary>> = Bin,
    {ok, #{
        signed => Signed,
        version => strip_zeroes(Version0),
        signer_id => SignerId,
        file_type => FileType,
        content_type => ContentType,
        content => Content,
        signature => Signature
    }}.

raw_rsa_sign(Digest, PrivKey) when is_tuple(PrivKey), tuple_size(PrivKey) >= 5 ->
    'RSAPrivateKey' = element(1, PrivKey),
    N = element(3, PrivKey),
    D = element(5, PrivKey),
    Encoded = crypto:mod_pow(Digest, D, N),
    Signature = binary:encode_unsigned(binary:decode_unsigned(Encoded)),
    pad_left(Signature, ?SIG_LEN_RSA_SHA512_4096).

pad_left(Bin, Size) when byte_size(Bin) < Size ->
    Padding = Size - byte_size(Bin),
    <<0:Padding/unit:8, Bin/binary>>;
pad_left(Bin, _Size) ->
    Bin.

-doc """
Verify an SU3 container's signature against a trust-anchor certificate.

Input: `Su3` — a decoded container; `CertDer` — DER-encoded X.509 certificate
whose RSA public key must have produced the signature.
Output: `ok` on a valid signature, `{error, bad_signature}` otherwise.
""".
-spec verify(su3(), binary()) -> ok | {error, bad_signature}.
verify(Su3, CertDer) ->
    #{signed := Signed, signature := Signature} = Su3,
    Digest = crypto:hash(sha512, Signed),
    Key = cert_public_key(CertDer),
    N = element(2, Key),
    E = element(3, Key),
    Recovered0 = crypto:mod_pow(binary:decode_unsigned(Signature), E, N),
    Recovered = pad_left(Recovered0, byte_size(Signature)),
    case byte_size(Recovered) >= byte_size(Digest) of
        true ->
            Size = byte_size(Digest),
            case binary:part(Recovered, byte_size(Recovered) - Size, Size) of
                Digest -> ok;
                _ -> {error, bad_signature}
            end;
        false ->
            {error, bad_signature}
    end.

-doc "The container's zero-stripped version string.".
-spec version(su3()) -> binary().
version(#{version := Version}) -> Version.

-doc "The container's signer identity (UTF-8).".
-spec signer_id(su3()) -> binary().
signer_id(#{signer_id := SignerId}) -> SignerId.

-doc "The declared file type byte (`0` = zip).".
-spec file_type(su3()) -> byte().
file_type(#{file_type := FileType}) -> FileType.

-doc "The declared content type byte (`3` = reseed data).".
-spec content_type(su3()) -> byte().
content_type(#{content_type := ContentType}) -> ContentType.

-doc "The raw content payload (for reseeds: a zip archive of RouterInfo .dat files).".
-spec content(su3()) -> binary().
content(#{content := Content}) -> Content.

-doc """
Extract the RSA public key of a DER-encoded X.509 certificate as an
`'RSAPublicKey'{}` record ready for `f:verify/2`.
""".
-spec cert_public_key(binary()) -> public_key:rsa_public_key().
cert_public_key(CertDer) ->
    {'Certificate', Tbs, _, _} = public_key:pkix_decode_cert(CertDer, plain),
    {'SubjectPublicKeyInfo', _, PubDer} = element(8, Tbs),
    public_key:der_decode('RSAPublicKey', PubDer).

-doc """
Check a certificate's validity window.

Input: `CertDer` — DER-encoded X.509 certificate; `UtcDateTime` — the moment
to test, as `calendar:datetime()`.
Output: `true` when `UtcDateTime` falls within `[notBefore, notAfter]`.
""".
-spec cert_valid_at(binary(), calendar:datetime()) -> boolean().
cert_valid_at(CertDer, UtcDateTime) ->
    {'Certificate', Tbs, _, _} = public_key:pkix_decode_cert(CertDer, plain),
    {'Validity', NotBefore, NotAfter} = element(6, Tbs),
    parse_time(NotBefore) =< UtcDateTime andalso UtcDateTime =< parse_time(NotAfter).

%%%%%%% %%% Internal %%%%%%%

%% strip_zeroes/1 — drop the spec-mandated zero padding from a version string.
strip_zeroes(<<>>) ->
    <<>>;
strip_zeroes(Bin) ->
    case binary:last(Bin) of
        0 -> strip_zeroes(binary:part(Bin, 0, byte_size(Bin) - 1));
        _ -> Bin
    end.

%% parse_time/1 — an ASN.1 'Time' (UTC or Generalized) to calendar datetime.
%% The characters arrive as ASCII code points; digits/1 folds each run into a
%% number. UTCTime carries a two-digit year, split at 50 per RFC 5280.
parse_time({utcTime, [Y1, Y2, M1, M2, D1, D2, H1, H2, Mi1, Mi2, S1, S2, $Z]}) ->
    {
        {two_digit_year(Y1, Y2), digits([M1, M2]), digits([D1, D2])},
        {digits([H1, H2]), digits([Mi1, Mi2]), digits([S1, S2])}
    };
parse_time({generalTime, [Y1, Y2, Y3, Y4, M1, M2, D1, D2, H1, H2, Mi1, Mi2, S1, S2, $Z]}) ->
    {
        {digits([Y1, Y2, Y3, Y4]), digits([M1, M2]), digits([D1, D2])},
        {digits([H1, H2]), digits([Mi1, Mi2]), digits([S1, S2])}
    }.

digits(Ds) ->
    lists:foldl(fun(C, Acc) -> (Acc * 10) + (C - $0) end, 0, Ds).

two_digit_year(Y1, Y2) when Y1 >= $5 -> 1900 + digits([Y1, Y2]);
two_digit_year(Y1, Y2) -> 2000 + digits([Y1, Y2]).
