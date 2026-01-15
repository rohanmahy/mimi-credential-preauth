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

TODO Abstract


--- middle

# Introduction

TODO Introduction


# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Structure of Credentials

Structured data formats use a handful of strategies for representing and organizing data.
All common structured data formats offer some type of record structure semantics. In this context this means a record contains a group of fields.
The names for record and fields differ across formats, as do their specific representations, as shown in the table below.

| Format | Representation of record | Identifier of field | Name of field |
|----
| CSV | line | position | field |
| TOML | group | name | entry? |
| SQL | row | column name | column/field |
| JSON | object (preferred) | name (quoted string) | value |
| JSON | array  | position | value |
| CBOR | map (slight preference) | (map) key (often integer) | value |
| CBOR | array  | position | element |
| ASN.1 | sequence | position or OID | element |
| ProtoBuf | struct or record? | field identifier? | ?? |
| msgpack | | | |
| XML | element | XMLPath or id attribute | contents of element |
| XML | attribute | XMLPath | value of attribute |
| YANG | | | |
| TLS PL | struct | field name | value |

In this document, we are primarily interested in structured formats commonly used in credentials, specifically JSON Web Tokens (JWT), CBOR Web Tokens (CWT), and X.509 certificates (ASN.1) and their derivatives.
In the context of credentials each of these specific fields is often described as a claim.

In X.509v3, a certificate contains an ASN.1 `SEQUENCE` of exactly 3 elements, the `tbsCertificate` ("to be signed certificate", which is analogous to the certificate payload), the signature algorithm, and the signature.
The certificate "payload" record is an ASN.1 `SEQUENCE` of 6 mandatory elements (certificate serial number, signature algorithm, issuer, validity, subject, and subject public key) and up to four optional elements (version, issuer unique ID, subject unique ID, and extensions).
For the purpose of matching elements in the sequence we will assign an index to each field (starting from 0) as if all 10 elements were present.
In this way, the overall structure is addressed by absolute position, while specific names, types, and extensions are identified using registered Object Identifiers (OIDs).
The extensions field contains a further syntax with a potentially large and varied basket of data structures.
Lists of items are represented as an ASN.1 `SEQUENCE OF` type, which if always of a single basic or composite type.
A composite type can contain a `CHOICE` of multiple subtypes.

In JSON, a record is represented as an object by convention. The individual fields in the record are identified by the object name, which is always a quoted string.
Very rarely a record is represented as an array of heterogeneous elements.
Credential claims in a JWT are present in the JWT payload object.
Lists of homogenous elements are also arrays.

In CBOR a record is typically represented as a map (very often with assigned integer map keys).
Records could also be represented as an array of heterogeneous elements.
Lists of homogenous elements are also arrays.

As in ASN.1, records and lists in JWT and CWT can be nested, sometimes deeply.
For example, the subjectAltName field can contain a list of different types of names (DNS, URI, email, etc.) that all represent the subject.
In JWT or CWT credentials, an address claim might consist of several component claims (ex: country or postal code); a language claim might consist of a list of languages; or a groups claim might contain nested claims only relevant to that specific group.

It is common to have a list of specific permission that have been granted in one context but not another.
For example a public relations manager might have regular access to resource A by virtue of being part of a company, access to resource B by virtue of being a full-time employee, regular access to resource C by virtue of being located in a particular country or office, moderator access to resource D by virtue of being a in public relations, and administrator access to resource E by virtue of being a manager.

# Requirements for Credential Inspection

The following requirements were considered necessary to have a successful credential matching mechanism.

1. The mechanism can detect the difference between no match, and a match with a null or undefined value.

2. The mechanism can find values in JSON objects and CBOR maps by the object name or key name.

3. The mechanism can find elements in ASN.1 by OID in a 2-element `SEQUENCE`.

4. The mechanism can find elements in lists or arrays by their position.

5. The mechanism can find elements in an ASN.1 `SEQUENCE` that has any combination of its optional elements.

6. The mechanism can find elements in array elements that have a single "identifying" field somewhere in the array value.

7. The mechanism can find elements in array elements that require identification by multiple matching claim pointers. - Maybe

8. The mechanism can find numerical values matching simple numeric predicates, such as great than, or less than or equal to.

9. The mechanism can find values matching well-defined parts of URIs and email addresses.

10. The mechanism can find values matching arbitrary substrings. - Maybe?

The following requirements were considered and rejected as out of scope.

- Can the mechanism find claim values matching regular expressions? No, since regular expressions often present a security footgun; as we are defined a mechanism expressly to be used with credentials, this is an unacceptable risk.

- Can the mechanism find claims using combinations of boolean logical statements containing OR statements in a claim pointer? No, as this is likely to allow an unbounded explosion of claim combinations, and an OR mechanism can be introduced at the level of the consuming application.

- Can the mechanism find claims with information from partial or incomplete nested map keys No, since JSON only supports strings as object names, and CWT does not map keys with maps or arrays. However this might be a straightforward extension.

- Can the mechanism find multiple claims with a given query? No, this would imply a mechanism that could return a set of arbitrarily disjoint trees, instead of returning a single result.


# Matching claims

In this section we introduce a method of matching claims in credentials that we describe here as Claim Pointers.
A claim pointer follows the hierarchy of a credential from its root to a specific claim, through a sequence of specifiers per level. Each level is described using a ClaimPointerUnit object.

For the purposes of this section, a level is hierarchy in JSON is the value of any object, or an element of an array. In CBOR a level of hierarchy is the value of any map key, an element of an array, or the contents of a tag. In ASN.1 a level of hierarchy is an item of either a `SEQUENCE` or `SEQUENCE OF`.

For the explanatory purposes, we will provide an example JWT payload here to demonstrate some of the claim matching options and introduce other examples as needed.

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


## Matching Map Keys, Object Names, and

The value of an object in JSON or a map in CBOR is accessed by its JSON name or CBOR map key, using the `map_key` pointer unit type.
For JSON the `opaque_key` to be compared with the key is a double-quoted JSON string that matches the object name.

For CBOR the `opaque_key` is the ordinary encoding that matches the map key.
For example the CBOR map keys of 1 (unsigned integer), -1 (negative integer), '1' (byte string), "1" (text string), 1(0) (a timestamp at the start of the UNIX epoch), and 1.0 (float) match the `opaque_key`s of 0x01, 0x20, 0x41 0x31, 0x61 0x31, 0xC1 0x00, and 0xF9 0x3C 0x00 respectively.

In X.509, a common pattern is to have a `SEQUENCE` of 2 elements consisting of an OID and data element (its "value").
The data element of such a 2 element `SEQUENCE` matches when its `opaque_key` is equal to the DER representation of its OID (excluding the OID type and length).

This pointer unit points to ("returns") the value corresponding to the object name, map key, or element in the `SEQUENCE`.

When evaluating the JWT payload above, the following claim pointer points at the value `true`, since that is the value of the `known_entity` claim.

~~~
claim_pointer = [
  [
    token_type = map_key,
    opaque_key = "known_entity"
  ]
]
~~~


## Matching Lists and Sequences by Absolute Position

The value of an element in an absolute position in a list is accessed using the `array_position` pointer unit type.
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
~~~

If there is no array, or the array does not have an element at the requested position, the claim pointer does not point at anything.
If the `index` above was instead 7, or the value of `service_flags` was not an array, the claim pointer would not point at any value.

As previously mentioned, the elements of an X.509 `SEQUENCE` with optional elements (such as `tbsCertificate`) are given a logical position from zero as if all possible optional elements are present.

## Matching an Element in a List by an Identifier in the List

The `array_search` claim pointer unit type, can search an array of an ASN.1  `SEQUNCE OF` for the first entry which matched the nested claim pointer in `nested_claim_pointer`.

The claim pointer below begins by pointing at the value of the entire `nodes` array.
Then, starting from the `nodes` array, its nested claim pointer points at the value of the `processor` object and compares it to the string value "DCBA-10177".
Finding a match, the top-level claim_pointer now points at the first element in the `nodes` array.
Finally, the next claim pointer unit looks for a `domain` object in the first element of the `nodes` array.
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
      match_on = utf8_ci,        /* UTF-8 case insensitive */
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
      match_on = domain_name,      /* match a valid domain   */
      test_value = "smart.example" /* with this value        */
    }]
  ], /* pointer is at first element of the nodes array */
  [
    token_type = map_key,
    opaque_key = "processor"
  ]
]
~~~

Finally, imagine that the value of the `domain` field was instead "xn--ingnieux-d1a.example", the `match_on` type was "punycode" and the `test_value` was "ingénieux.example".
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
        match_on = domain_name,      /* match a valid domain   */
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
        match_on = utf8ci,
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
~~~


## Matching with Numerical Predicates

~~~
  test_value = "eur_per_hour"

value_semantics = number,
match_on = number,
operation = greater_or_equal,
test_value = 200.0
~~~



## Matching Parts of URIs and email addresses

~~~
value_semantics = uri,
match_on = hostpart,
test_value = "example.com"
~~~

## Matching Arbitrary Substrings

mimi://example.com/u/46133c9e-df4c-4c88-91d2-00a527bdd0f7

~~~
value_semantics = uri,
match_on = uripath,
operation = substring,
  start = 3,
  length = 36
test_value = "46133c9e-df4c-4c88-91d2-00a527bdd0f7"
~~~

# some scraps here


A ClaimPointerUnit can consist of a handful of types

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
match_on = bool,
opaque_value = true
MATCH

claim_pointer = [
  [
    token_type = map_key,
    opaque_key = "some_nonexistent_key"
  ]
]
/* value is null */
match_on = bool,
opaque_value = true
NO MATCH

claim_pointer = [
  [
    token_type = array_position,
    index = 3
  ]
]
/* value is null (there is no array or has fewer elements) */
match_on = utf8_ci,
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
match_on = bool,
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
    match_on = string,
    test_value = "DCBA-10177"
    MATCH
  ], /* pointer is at first element of the nodes array */
  [
    token_type = map_key,
    opaque_key = "domain"
  ]
]
/* value is [ "smart.example" ] */
match_on = domain
opaque_value = "smart.example"
MATCH
~~~



Imagine the match is on an IDN domain and the value of the `domain` object was "xn--ingnieux-d1a.example".

match_on = punycode
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
    match_on = string,
    test_value = "us"
    MATCH
  ], /* pointer is at first element of the nodes array */
  [
    token_type = map_key,
    opaque_key = "domain"
  ]
]
/* value is [ "smart.example" ] */
match_on = domain
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
    bytes (0),
    string (1),
    domain (2),
    uri (3),
    email (4),
    (255)
} ClaimSemantics;

enum {
    bytes (0),
    utf8 (1),
    domain (2),
    user_id (3),
    device_id (4),
    handle (5),
    userpart (6),
    hostpart (7),
    uri_path (8),
    (255)
} MatchOn;

enum {
    member_name (0),
    array_index (1),
    (255)
} JwtTokenType;

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
} CwtTokenType;

struct {
    CwtTokenType token_type;
    select (token_type) {
        case map_key:
            opaque key<V>;
        case array_index:
            uint index;
        case tagged_value:
            struct {}
        case bstr_encoded:
            struct {}
    }
} CwtToken;

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
    MatchOn match_on;
    bool match_any_in_list;
    opaque target_value<V>;
} Claim;
~~~



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
    match_on = domain / userpart / user_id
    test_value = "provider.example"
    MATCH
  ] /* value is [ ["URI", "https://provider.example/path"] ] */
],
semantics = uri,
match_on = exists,
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
