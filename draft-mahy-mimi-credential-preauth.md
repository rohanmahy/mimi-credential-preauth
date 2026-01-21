---
title: "MIMI Preauthorization based on deep references to MLS Credentials"
abbrev: "MIMI Deep Credential Preauth"
category: info

docname: draft-mahy-mimi-credential-preauth-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Applications and Real-Time"
workgroup: "More Instant Messaging Interoperability"
keyword:
 - preauthorization
 - credential
 - CWT
 - JWT
 - X.509
 - ASN.1
 - DER
 - credential matching
 - credential comparison
venue:
  group: "More Instant Messaging Interoperability"
  type: "Working Group"
  mail: "mimi@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/mimi/"
  github: "rohanmahy/mimi-credential-preauth"
  latest: "https://rohanmahy.github.io/mimi-credential-preauth/draft-mahy-mimi-credential-preauth.html"

author:
 -
    fullname: Rohan Mahy
    email: rohan.ietf@gmail.com

normative:

informative:

...

--- abstract

This document describes a syntax called claim pointers that identify specific items in structured credentials, which often have nested levels of hierarchy;
and claim matchers that facilitate comparisons between items in credentials and a target value.
It also describes a new version of the More Instant Messaging Interoperability (MIMI) preauthorization format using claim pointers and claim matchers.

--- middle

# Introduction

More Instant Messaging Interoperability (MIMI) room policy ({{!I-D.ietf-mimi-room-policy}}) defines a format that allows potential joiners that are not enumerated beforehand to be preauthorized based on properties found in their Messaging Layer Security (MLS) {{!RFC9420}} credentials.
The current version of the preauthorization format in {{Section 4 of !I-D.ietf-mimi-room-policy}} is underspecified and was designed to work with individual claims in a JSON Web Token (JWT) {{!RFC7519}} or CBOR Web Token (CWT) {{!RFC8392}}.
This document describes a syntax called claim pointers that can address claims nested inside JWT, CWT, and X.509 certificates {{!RFC5280}}, and provides richer matching rules called claim matchers, capable of matching sub parts of those claims and predicates based on them.
It could also be extended to credentials based on most general purpose structured data formats.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Structure of Credentials

Structured data formats use a handful of strategies for representing and organizing data.
All common structured data formats offer some type of record structure semantics. In this context this means a record contains a group of fields.
The names for record and fields differ across formats, as do their specific representations, as shown in the table below.

| Format | Representation of record | Identifier of field | Name of field |
|----
| JSON | object (preferred) | name (quoted string) | value |
| JSON | array  | position | value |
| CBOR | map (slight preference) | map key (often an integer) | value |
| CBOR | array  | position | element |
| ASN.1 | sequence | position or OID | element |
| TLS PL | struct | field name | value |
| TLS PL | vector (not used for records) | position | value |
| ProtoBuf | struct or record? | integer field identifier | ?? |
| msgpack | | | |
| XML | element | XMLPath or id attribute | contents of element |
| XML | attribute | XMLPath | value of attribute |
| CSV | line | position | field |
| TOML | group | name | entry? |
| SQL | row | column name | column/field |
| YANG | | | |

In this document, we are primarily interested in structured formats commonly used in credentials, specifically JSON Web Tokens (JWT), CBOR Web Tokens (CWT), and X.509 certificates (which use ASN.1) and their derivatives.
In the context of credentials, each of these specific fields is often described as a claim.

In JSON, a record is represented as an object by convention. The individual fields in the record are identified by the object name, which is always a quoted string.
Very rarely a record is represented as an array of heterogeneous elements.
Credential claims in a JWT are present in the JWT payload object.
Lists of homogenous elements are also arrays.

In CBOR a record is typically represented as a map (very often with assigned integer map keys).
Records could also be represented as an array of heterogeneous elements.
Lists of homogenous elements are also arrays.

In X.509v3, a certificate contains an ASN.1 `SEQUENCE` of exactly 3 elements, the `tbsCertificate` ("to be signed certificate", which is analogous to the certificate payload), the signature algorithm, and the signature.
The certificate "payload" record is an ASN.1 `SEQUENCE` of 6 mandatory elements (certificate serial number, signature algorithm, issuer, validity, subject, and subject public key) and up to four optional elements (version, issuer unique ID, subject unique ID, and extensions).
For the purpose of matching elements in the sequence we will assign an index to each field (starting from 0) as if all 10 elements were present.
In this way, the overall structure is addressed by absolute position, while specific names, types, and extensions are identified using registered Object Identifiers (OIDs).
The X.509 certificate extensions field contains a further syntax with a potentially large and varied basket of data structures.
Lists of items are represented as an ASN.1 `SEQUENCE OF` type, which is always of a single basic or composite type.
A composite type can contain a `CHOICE` of multiple subtypes.

Records and lists in JSON, CBOR, and ASN.1 can be nested, sometimes deeply.
For example, the X.509 `subjectAltName` extension can contain a list of different types of names (DNS, URI, email, etc.) that all represent the subject.
In JWT or CWT credentials, an address claim might consist of several component claims (ex: country or postal code); a language claim might consist of a list of languages; or a groups claim might contain nested claims only relevant to that specific group.

It is common to have a list of specific permission that have been granted in one context but not another.
For example a public relations manager might have regular access to resource A by virtue of being part of a company, access to resource B by virtue of being a full-time employee, regular access to resource C by virtue of being located in a particular country or office, moderator access to resource D by virtue of being a in public relations, and administrator access to resource E by virtue of being a manager.

# Requirements for Credential Inspection

The following requirements were considered necessary to have a successful credential matching mechanism.

1. The mechanism can represent the difference between no match, and a match with a null or undefined value.

2. The mechanism can find a value in a JSON object or CBOR map by the object name or key name.

3. The mechanism can find an element in ASN.1 by its OID in a `SET` containing a two-element `SEQUENCE`.

4. The mechanism can find an element in a list, array, or `SEQUENCE OF` by its position.

5. The mechanism can find an element in an ASN.1 `SEQUENCE` that has any combination of its optional elements.

6. The mechanism can find a single element in an list or array where one of the list/array elements contains a single "identifying" field somewhere in the array value.

7. The mechanism can find an element among array elements that requires identification by multiple claim matchers joined with boolean logical ANDs (**Maybe**).

8. The mechanism can find a numerical value matching simple numeric predicates, such as greater than, or less than or equal to a target value.

9. The mechanism can match a target value to a well-defined part of a URI and email address claim.

10. The mechanism can compare a target value to an arbitrary substring of a value identified by a claim pointer (**Maybe**).

The following requirements were considered and rejected as out of scope.

- Can the mechanism find claim values matching regular expressions? No, since regular expressions often present a security footgun; as we are defining a mechanism expressly to be used with credentials, this is an unacceptable risk.

- Can the mechanism find claims using arbitrary combinations of boolean logical statements containing OR statements in a claim pointer? No, as this is likely to allow an unbounded explosion of claim combinations, and an OR mechanism can be introduced at the level of the application using the claim pointer mechanism.

- Can the mechanism find claims with information from partial or incomplete nested map keys? No, since JSON only supports strings as object names, and CWT does not map keys with maps or arrays. However, this might be a straightforward extension.

- Can the mechanism find multiple claims with a given query? No, this would imply a mechanism that could return a set of arbitrarily disjoint trees, instead of returning a single result (or no match).


# Matching claims

In this section we introduce a method of matching claims in credentials that we describe here as Claim Pointers (which find a particular value), and Claim Matchers (which compare a value from a Claim Pointer to a specific value).
A claim pointer follows the hierarchy of a credential from its root to a specific claim, through a sequence of specifiers per level. Each level is described using a `ClaimPointerItem` object.

For the purposes of this section, a level of hierarchy in JSON is the value of any object, or an element of an array. In CBOR a level of hierarchy is the value of any map key, an element of an array, or the contents of a tag. In ASN.1 a level of hierarchy is generally an element of either a `SEQUENCE` or `SEQUENCE OF`.

For explanatory purposes, we will provide an example JWT payload here to demonstrate some of the claim matching options. Additional examples will be introduced as needed.

~~~ json
{                                   # contents are at level 1
  "iss": "https://issuer.example",
  ...
  "known_entity": true,
  "orig_timestamp": 1549560720,
  "nodes": [                        # contents are at level 2
    {                               # contents are at level 3
      ...
      "processor": "DCBA-101777",
      "origin": {                   # contents are at level 4
        "country": "us",
        ...
      },
      "domain": "smart.example"
      "eur_per_hour": 273.15
    },
    ...
  ],
  "service_flags": [false, false, true, false]
}
~~~


## Matching Map Keys, Object Names, and OIDs

The value of an object in JSON or the value of a map in CBOR is accessed by its JSON name or CBOR map key, using the `via_key` pointer item type.
For JSON the `key` to be compared with the key is a double-quoted JSON string that matches the object name.

For CBOR the `key` is the ordinary encoding {{!I-D.ietf-cbor-serialization}} that matches the map key.
For example the CBOR map keys of 1 (unsigned integer), -1 (negative integer), '1' (byte string), "1" (text string), 1(0) (a timestamp at the start of the UNIX epoch), and 1.0 (float) match the `key`s of 0x01, 0x20, 0x41 0x31, 0x61 0x31, 0xC1 0x00, and 0xF9 0x3C 0x00 respectively.

In X.509, a common pattern is to have a single element `SET` of a `SEQUENCE` of two elements consisting of an OID and data element (its "value").
The data element of such a 2 element `SEQUENCE` matches when its `key` is equal to the DER representation of its OID (excluding the OID type and length).

This pointer item points to ("returns") the value corresponding to the object name, map key, or element in the `SEQUENCE`.

When evaluating the JWT payload above, the following claim pointer points at the value `true`, since that is the value of the `known_entity` claim.

~~~
claim_pointer = [
  [
    token_type = map_key,
    opaque_key = "known_entity"
  ]
]
claim_pointer[0].unit_type = map_key; /* 0 */
claim_pointer[0].opaque_key = "known_entity";


/* This feels like nicer names to me */
pointer_item[0].unit_match = via_key;
pointer_item[0].key.type = string;
pointer_item[0].key.value = "known_entity";
~~~


## Matching Lists and Sequences by Absolute Position

The value of an element in an absolute position in a list is accessed using the `array_position` pointer item type.
The `index` value corresponds to the position counting from 0.

The claim pointer below using the example JSON document above would point at the value `true` as well, the 3rd element of the `service_flags` array.

~~~
claim_pointer = [
  [
    token_type = map_key,
    opaque_key = "service_flags"
  ],  /* points to entire array */
  [
    token_type = array_position,
    index = 2
  ]
]

/* claim_pointer[0] points to entire array */
claim_pointer[0].unit_type = map_key; /* 0 */
claim_pointer[0].opaque_key = "service_flags";

/* claim_pointer[1] points to 3rd element (true) */
claim_pointer[1].unit_type = array_position; /* 1 */
claim_pointer[1].index = 2;
~~~

If there is no array, or the array does not have an element at the requested position, the claim pointer does not point at anything.
If the `index` above was instead 7, or the value of `service_flags` was not an array, the claim pointer would not point at any value.

As previously mentioned, the elements of an X.509 `SEQUENCE` with optional elements (such as `tbsCertificate`) are given a logical position from zero as if all possible optional elements are present.

## Matching an Element in a List by an Identifier in the List

The `array_search` claim pointer item type, can search a JSON or CBOR array, or an ASN.1  `SEQUNCE OF`, for the first entry which matched the nested claim matchers in `nested_claim_pointer`.

The claim pointer below begins by pointing at the value of the entire `nodes` array.
Then, starting from the `nodes` array, its nested claim pointer points at the value of the `processor` object and compares it to the string value "DCBA-10177".
Finding a match, the top-level claim_pointer now points at the first element in the `nodes` array.
Finally, the next claim pointer item looks for a `domain` object in the first element of the `nodes` array.
The claim pointer now points at the value "smart.example".

~~~
claim_pointer = [
  [
    token_type = map_key,
    opaque_key = "nodes"
  ], /* points to entire array of nodes elements */
  [
    token_type = array_search,
    nested_claim_pointer = [{
      claim_pointer = [
        [
          token_type = map_key,
          opaque_key = "processor"
        ]    /* find an element with a `processor` object */
      ],
      value_semantics = string,  /* of type string         */
      match_as = utf8_ci,        /* UTF-8 case insensitive */
      test_value = "DCBA-10177"  /* matching this value    */
    }]
  ], /* pointer is at first element of the nodes array */
  [
    token_type = map_key,
    opaque_key = "domain"
  ]
]
~~~

Instead imagine searching for the value of `processor` in the first element that matches the `domain` "smart.example".
We would use the following claim_pointer instead, which would point to the value "DCBA-10177" in the first element's `processor` object.

~~~
claim_pointer = [
  [
    token_type = map_key,
    opaque_key = "nodes"
  ], /* points to entire array of nodes elements */
  [
    token_type = array_search,
    nested_claim_pointers = [{
      claim_pointer = [
        [
          token_type = map_key,
          opaque_key = "domain"
        ]    /* find an element with a `domain` object */
      ],
      value_semantics = domain,    /* of type domain         */
      match_as = domain_name,      /* match a valid domain   */
      test_value = "smart.example" /* with this value        */
    }]
  ], /* pointer is at first element of the nodes array */
  [
    token_type = map_key,
    opaque_key = "processor"
  ]
]
~~~

Finally, imagine that the value of the `domain` field was instead "xn--ingnieux-d1a.example", the `match_as` type was "punycode" and the `test_value` was "ingénieux.example".
This would also point to the same value ("DCBA-10177") since the punycode representation of the Internationalized Domain Name (IDN) or "punycode" representation of "ingénieux.example" is "xn--ingnieux-d1a.example".

## Matching multiple claim pointers


~~~
claim_pointer = [
  [
    token_type = map_key,
    opaque_key = "nodes"
  ], /* points to entire array of nodes elements */
  [
    token_type = array_search,
    nested_claim_pointers = [
      {
        claim_pointer = [
          [
            token_type = map_key,
            opaque_key = "domain"
          ]    /* find an element with a `domain` object */
        ],
        value_semantics = domain,    /* of type domain         */
        match_as = domain_name,      /* match a valid domain   */
        test_value = "smart.example" /* with this value        */
      },
      {
        claim_pointer = [
          [
            token_type = map_key,
            opaque_key = "origin"
          ],
          [
            token_type = map_key,
            opaque_key = "country"
          ]
        ],
        value_semantics = string,
        match_as = utf8ci,
        test_value = "us"
      }
    ] /* first element with both country = us           */
      /*                     AND domain = smart.example */
  ], /* pointer is at first element of the nodes array */
  [
    token_type = map_key,
    opaque_key = "processor"
  ]
]

pointer_item[0].unit_match = via_key;
pointer_item[0].key.type = string;
pointer_item[0].key.value = "nodes";
pointer_item[1].unit_match = via_array_search;
pointer_item[1].claim_match[0].pointer_item[0].unit_match = via_key;
pointer_item[1].claim_match[0].pointer_item[0].key.type = string;
pointer_item[1].claim_match[0].pointer_item[0].key.value = "domain"
pointer_item[1].claim_match[0].semantics = domain
pointer_item[1].claim_match[0].match = domain
pointer_item[1].claim_match[0].value = "smart.example"
pointer_item[1].claim_match[1].pointer_item[0].unit_match = via_key;
pointer_item[1].claim_match[1].pointer_item[0].key.type = string;
pointer_item[1].claim_match[1].pointer_item[0].key.value = "origin"
pointer_item[1].claim_match[1].pointer_item[1].unit_match = via_key;
pointer_item[1].claim_match[1].pointer_item[1].key.type = string;
pointer_item[1].claim_match[1].pointer_item[1].key.value = "country";
pointer_item[1].claim_match[1].semantics = string;
pointer_item[1].claim_match[1].match = utf8_ci;
pointer_item[1].claim_match[1].value = "us";
pointer_item[2].unit_match = via_key;
pointer_item[2].key.type = string;
pointer_item[2].key.value = "processor";
~~~


## Matching with Numerical Predicates

~~~
  test_value = "eur_per_hour"

value_semantics = number,
match_as = number,
operation = greater_or_equal,
test_value = 200.0
~~~



## Matching Parts of URIs and email addresses

~~~
value_semantics = uri,
match_as = hostpart,
test_value = "example.com"
~~~

## Matching Arbitrary Substrings

mimi://example.com/u/46133c9e-df4c-4c88-91d2-00a527bdd0f7

~~~
value_semantics = uri,
match_as = uripath,
operation = substring,
  start = 3,
  length = 36
test_value = "46133c9e-df4c-4c88-91d2-00a527bdd0f7"
~~~

# some scraps here


A ClaimPointerItem can consist of a handful of types

`map_key`



`array_index`

`index` matches the 0-indexed element of the array


`array_search`

matches the first element in the searched array which matches all of the `nested_claim_pointers`

it returns the value of the found array element


for example


`map_search`

is less commonly used, but needed when accessing a map key that itself has a nested structure






~~~ json
{
  "abc": "foo"
  "def": [
     "carrot",
     "tomato",
     2.5,
     true
  ],
  "ghi": [
    [
    ],
    [
    ],
    {
      "roles": ["Employees", "Boston", "PR", "Manager"],
      "start_date": "01-Apr-2021"
    }
  ],
  "jkl": {
     "AAA": "all \"a\"'s",
     "BBB": "all b's"
  },
  "xyz": 1.0
}
~~~

~~~
claim_pointer = [
  [
    token_type = map_key,
    opaque_key = "known_entity"
  ]
]
match_as = bool,
opaque_value = true
MATCH

claim_pointer = [
  [
    token_type = map_key,
    opaque_key = "some_nonexistent_key"
  ]
]
/* value is null */
match_as = bool,
opaque_value = true
NO MATCH

claim_pointer = [
  [
    token_type = array_position,
    index = 3
  ]
]
/* value is null (there is no array or has fewer elements) */
match_as = utf8_ci,
opaque_value = "us"
NO MATCH


claim_pointer = [
  [
    token_type = map_key,
    opaque_key = "service_flags"
  ],  /* points to entire array */
  [
    token_type = array_position,
    index = 2
  ]
]
/* value is [ true ] (value of 3rd element in array) */
match_as = bool,
opaque_value = true
MATCH

claim_pointer = [
  [
    token_type = map_key,
    opaque_key = "nodes"
  ], /* points to entire array of nodes elements */
  [
    token_type = array_search,
    nested_claim_pointer = [
      [
        token_type = map_key,
        opaque_value = "processor"
      ]
    ],
    match_as = string,
    test_value = "DCBA-10177"
    MATCH
  ], /* pointer is at first element of the nodes array */
  [
    token_type = map_key,
    opaque_key = "domain"
  ]
]
/* value is [ "smart.example" ] */
match_as = domain
opaque_value = "smart.example"
MATCH
~~~



Imagine the match is on an IDN domain and the value of the `domain` object was "xn--ingnieux-d1a.example".

match_as = punycode
test_value = "ingénieux.example"


~~~
claim_pointer = [
  [
    token_type = map_key,
    opaque_key = "nodes"
  ], /* points to entire array of nodes elements */
  [
    token_type = array_search,
    nested_claim_pointer = [
      [
        token_type = map_key,
        opaque_value = "origin"
      ], /* value of first element is origin map */
      [
        token_type = map_key,
        test_value = "country"
      ] /* value of first element is "us" */
    ],
    match_as = string,
    test_value = "us"
    MATCH
  ], /* pointer is at first element of the nodes array */
  [
    token_type = map_key,
    opaque_key = "domain"
  ]
]
/* value is [ "smart.example" ] */
match_as = domain
opaque_value = "smart.example"
MATCH


~~~
NEXT example match both processor and domain in array_search
claim_pointer =


NEXT example match predicate ≥ 200.00 eur per hour
does this require ANDs to get ranges?

NEXT example well-defined parts of URIs and email


NEXT example substrings


# Match Syntax Definition

~~~ tls
enum {
    reserved (0),
    x509 (1),
    jwt (2),
    cwt(3),
    (255)
} ClaimFamily;

enum {
    null (0),
    number (1),
    int (2),
    float (3),
    bool (4),
    date (5),
    bytes (6),
    string (7),
    domain (8),
    uri (9),
    https_uri (10),
    mimi_uri (11),
    email (12),
    (255)
} ClaimSemantics;

enum {
    exists (0),
    number (1),
    int (2),
    uint (3),
    float (4),
    finite_float (5),
    bool (6),
    secs_since_epoch (7),
    iso8601 (8),
    bytes (9),
    hex (10),
    base64 (11),
    base64url (12),
    der (13),
    pem (14),
    ipv4 (15),
    ipv6 (16),
    deterministic_cbor (17),
    utf8 (18),
    utf8_ci (19),
    nfc (20),
    nfd (21),
    canonical_json (22),
    domain (23),
    punycode (24),
    email_address (25),
    generic_uri (26),
    https_uri (27),
    userpart (28),
    hostpart (29),
    uri_path (30),
    mimi_uri (31),
    user_id (32),
    device_id (33),
    room_id (34),
    (255)
} MatchAs;

enum {
    member_name (0),
    array_position (1),
    array_search (2),
    tagged_value (3), /* CBOR only */
    bstr_encoded (4), /* CBOR only */
    (255)
} ClaimItemType;




struct {
    JwtTokenType token_type;
    select (token_type) {
        case member_name:
            opaque name<V>;
        case array_index:
            uint index;
    }
} JwtToken;

struct {
    JwtToken claim_pointer<V>;
} JwtClaimRoot;

enum {
    map_key (0),
    array_index (1),
    tagged_value (2),
    bstr_encoded (3),
    (255)
} TokenType;

struct {
    TokenType token_type;
    select (token_type) {
        case map_key:
            opaque opaque_key<V>;
        case array_index:
            uint index;
        case array_search:
            ClaimMatcher nested_matches<V>;
        case tagged_value:
            uint tag;
        case bstr_encoded:
            struct {};
    }
} ClaimPointerItem;

enum {
    equal (0),
    less_than (1),
    less_than_or_equal (2),
    greater_than (3),
    greater_than_or_equal (4),
    len_bytes,
    len_chars,
    contains,
    starts_with,
    ends_with,
    substring,
    path_slice,
} OperationType;

struct {
  OperationType operation_type;
  select (operation_type) {
    case starts_with:
        optional<uint> length;
    case ends_width:
        optional<uint> length;
    case substring:
        uint start_position;
        uint length;
    case path_slice:
        uint path_index;
  };
} Operation;

struct {
    ClaimPointerItem claim_pointer<V>;
    ClaimSemantics claim_semantics;
    MatchAs match_as;
    optional<Operation> operation;
    opaque matching_value<V>;   /* maybe test_value */
} ClaimMatcher;

struct {
    ClaimFamily claim_family;
    select (claim_family) {
        case json:
            JsonType json_type;
            select (json_type) {
                case number:
                    Double value;
                case string:
                case object:
                case array:
                    Bytes value;
                case no_match:
                case true:
                case false:
                case null:
                    struct {};
            }
        case cbor:
            Bytes cbor_encoding;
        case asn1:
    };
} MapKey

case no_match:
    struct {};
case uint:
case nint:
    uint64 value;
case float
    Double value;
case array:
case map:
case text_string:
case byte_string:
    Bytes value;
case tag:
    uint64 tag;
    Bytes value;
case undefined:
    select {};
case simple:
    uint8 value;


enum JsonType {
    no_match (0),
    number (1),
    string (2),
    object (3),
    array (4),
    true (5),
    false (6),
    null (7)
    (255)
}



struct {
    CwtToken claim_pointer<V>;
} CwtClaimRoot;

struct {
    ClaimFamily claim_family;
    select (claim_family) {
        case x509:
            opaque oid<V>;
        case jwt:
            JwtClaimRoot claim_root;
        case cwt:
            CwtClaimRoot claim_root;
    }
    ClaimSemantics claim_semantics;
    MatchAs match_as;
    bool match_any_in_list;
    opaque target_value<V>;
} Claim;
~~~

# Types of comparisons

`exists`
number,
int,
uint,
float,
finite_float,
bool,
`secs_since_epoch` convert into a Javascript date (seconds since the epoch )
    iso8601,
    bytes (0),
    hex,
    base64,
    base64url,
    der,
    pem,
    ipv4,
    ipv6,
    deterministic_cbor,
    utf8 (1),
    utf8_ci ,
    nfc,
    nfd,
    canonical_json,
    domain (2),
    punycode,
    email_address,
    generic_uri,
    https_uri,
    userpart (6),
    hostpart (7),
    uri_path (8),
    mimi_uri,
    user_id (3),
    device_id (4),
    room_id (5),
    (255)




# More examples

## CBOR Examples

~~~ cbor-diag
{                                   # contents are level 1
  1: "https://issuer.example",
  ...
  502: 1(1549560720),               # tagged value is level 2
  504: [                            # contents are level 2
    {                               # contents are level 3
      ...
      501: "DCBA-101777",
      503: {                        # contents are level 4
        1: "us",
        ...
      },
      505: 4(                       # decimal fraction tag
        [                           #   273.15
          -2,
          27315                     # level 5
        ]
      )
    },
    ...
  ],
  509: [false, false, true, false]
}
~~~

### CBOR example with tagged value access directly as opaque_value

### CBOR example parsing into tagged value

### CBOR example with custom simple values ?? - maybe not needed

## X.509 Examples

~~~

SEQUENCE (1 elem)
  SET (1 elem)
    SEQUENCE (2 elem)
      OBJECT IDENTIFIER 2.5.4.3 commonName (X.520 DN component)
      PrintableString github.com
...
    SEQUENCE (3 elem)
      OBJECT IDENTIFIER 2.5.29.15 keyUsage (X.509 extension)
      BOOLEAN true
      OCTET STRING (4 byte) 03020780
        BIT STRING (1 bit) 1
    SEQUENCE (3 elem)
      OBJECT IDENTIFIER 2.5.29.19 basicConstraints (X.509 extension)
      BOOLEAN true
      OCTET STRING (2 byte) 3000
        SEQUENCE (0 elem)
    SEQUENCE (2 elem)
      OBJECT IDENTIFIER 2.5.29.37 extKeyUsage (X.509 extension)
      OCTET STRING (22 byte) 301406082B0601050507030106082B06010505070302
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 1.3.6.1.5.5.7.3.1 serverAuth (PKIX key purpose)
          OBJECT IDENTIFIER 1.3.6.1.5.5.7.3.2 clientAuth (PKIX key purpose)
...
    SEQUENCE (2 elem)
      OBJECT IDENTIFIER 2.5.29.17 subjectAltName (X.509 extension)
      OCTET STRING (30 byte) 301C820A6769746875622E636F6D820E7777772E6769746875622E636F6D
        SEQUENCE (2 elem)
          [2] (10 byte) github.com
          [2] (14 byte) www.github.com
~~~

### Simple X.509 example (CN)

### X.509 Matching one DNS item in issuerAltName

### X.509 matching one URI part of subjectAltName

### X.509 matching one URI part of subjectAltName with a domain substring







~~~
claim_pointer = [
  [
    type = oid,
    value = 2.5.29.17 = 0x55 1d 11   # subjectAltName
  ],
  [
    type = array_serach,
    nested_claim_pointer = [
      [
      ]
    ],
    semantics = uri,
    match_as = domain / userpart / user_id
    test_value = "provider.example"
    MATCH
  ] /* value is [ ["URI", "https://provider.example/path"] ] */
],
semantics = uri,
match_as = exists,
test_value = true
MATCH

try email?  match domain in nester pointer, match on user in main match??
~~~

RFC5820 matches only host part of URIs??







# Old text on Preauth

Preauthorized users are MIMI users and external senders that have authorization to adopt a role in a room by virtue of certain credential claims or properties, as opposed to being individually enumerated in the participant list.
For example, a room for employee benefits might be available to join with the regular participant role to all full-time employees with a residence in a specific country; while anyone working in the human resources department might be able to join the same room as a moderator.
This data structure is consulted in two situations: for external joins (external commits) and external proposals when the requester does not already appear in the participant list; and separately when an existing participant explicitly tries to change its *own* role.

>Only consulting Preauthorized users in these cases prevents several attacks. For example, it prevents an explicitly banned user from rejoining a group based on a preauthorization.

PreAuthData is the format of the `data` field inside the ComponentData struct for the Preauthorized Participants component in the `application_data` GroupContext extension.

The individual `PreAuthRoleEntry` rules in `PreAuthData` are consulted one at a time.
A `PreAuthRoleEntry` matches for a requester when every `Claim.claim_id` has a corresponding claim in the requester's MLS Credential which exactly matches the corresponding `claim_value`.
When the rules in a Preauthorized users struct match multiple roles, the requesting client receives the first role which matches its claims.

> **TODO**: refactor Claims

~~~ tls-presentation
struct {
  /* MLS Credential Type of the "claim"  */
  CredentialType credential_type;
  /* the binary representation of an X.509 OID, a JWT claim name  */
  /* string, or the CBOR map claim key in a CWT (an int or tstr)  */
  opaque id<V>;
} ClaimId;

struct {
  ClaimId claim_id;
  opaque claim_value<V>;
} Claim;

struct {
  /* when all claims in the claimset are satisfied, the claimset */
  */ is satisfied */
  Claim claimset<V>;
  Role target_role;
} PreAuthRoleEntry;

struct {
  PreAuthRoleEntry preauthorized_entries<V>;
} PreAuthData;

PreAuthData preauth_list;
PreAuthData PreAuthUpdate;
~~~

<!--
struct {
  select (Credential.credential_type) {
    case basic:
        struct {}; /* only identity */
    case x509:
        /* ex: subjectAltName (2.5.29.17) = hex 06 03 55 1d 1e */
        opaque oid<V>;
        /* for sequence or set types, the specific item (1-based) */
        /* in the collection. zero means any item in a collection */
        uint8 ordinal;
    case jwt:
        opaque json_path<V>;
    case cwt:
        CborKeyNameOrArrayIndex cbor_path<V>;
  };
} Claim;

struct {
    /* a CBOR CDE encoded integer, tstr, bstr, or tagged version of */
    /* any of those map key types. Ex: -1 = 0x20, "hi" = 0x626869,  */
    /* 1(3600) = 0xC1190E10 */
    opaque cbor_encoded_claim<V>;
    optional uint array_index;
} CborKeyNameOrArrayIndex;
-->

PreAuthUpdate (which has the same format as PreAuthData) is the format of the `update` field inside the AppDataUpdate struct in an AppDataUpdate Proposal for the Preauthorized Participants component.
If the contents of the `update` field are valid and if the proposer is authorized to generate such an update, the value of the `update` field completely replaces the value of the `data` field.

>As with the definition of roles, in MIMI it is not expected that the definition of Preauthorized users would change frequently. Instead the claims in the underlying credentials would be modified without modifying the preauthorization policy.

Changing Preauthorized user definitions is sufficiently disruptive, that an update to this component is not valid if it appears in the same commit as any Participant List change, except for user removals.

Because the Preauthorized users component usually authorizes non-members, it is also a natural choice for providing concrete authorization for policy enforcing systems incorporated into or which run in coordination with the MIMI Hub provider or specific MLS Distribution Services. For example, a preauthorized role could allow the Hub to remove participants and to ban them, but not to add any users or devices. This unifies the authorization model for members and non-members.




# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
