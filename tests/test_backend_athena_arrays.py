import pytest
from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingPipeline

from sigma.backends.athena import athenaBackend


@pytest.fixture
def athena_backend():
    return athenaBackend(array_fields=["dns.answers", "tags"])


def test_array_struct_list(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: Struct Array List
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                sel:
                    dns.answers.name:
                        - '127.0.0.1'
                        - '0.0.0.0'
                condition: sel
        """))
        == [
            "SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(dns.answers, _sigma_element -> LOWER(_sigma_element.name) IN ('127.0.0.1', '0.0.0.0')), FALSE)"
        ]
    )


def test_array_scalar_list(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: Scalar Array List
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                sel:
                    tags:
                        - '127.0.0.1'
                        - '0.0.0.0'
                condition: sel
        """))
        == [
            "SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(tags, _sigma_element -> LOWER(_sigma_element) IN ('127.0.0.1', '0.0.0.0')), FALSE)"
        ]
    )


def test_array_string_equality(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: Array String Equality
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                scalar:
                    tags: Foo
                struct:
                    dns.answers.name: Foo
                condition:
                    - scalar
                    - struct
        """))
        == [
            "SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(tags, _sigma_element -> LOWER(_sigma_element) = 'foo'), FALSE)",
            "SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(dns.answers, _sigma_element -> LOWER(_sigma_element.name) = 'foo'), FALSE)",
        ]
    )


def test_array_cased_equality(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: Array Cased Equality
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                scalar:
                    tags|cased: Foo
                struct:
                    dns.answers.name|cased: Foo
                condition:
                    - scalar
                    - struct
        """))
        == [
            "SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(tags, _sigma_element -> _sigma_element = 'Foo'), FALSE)",
            "SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(dns.answers, _sigma_element -> _sigma_element.name = 'Foo'), FALSE)",
        ]
    )


def test_array_cased_list(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: Array Cased List
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                scalar:
                    tags|cased:
                        - Foo
                        - Bar
                struct:
                    dns.answers.name|cased:
                        - Foo
                        - Bar
                condition:
                    - scalar
                    - struct
        """))
        == [
            "SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(tags, _sigma_element -> _sigma_element IN ('Foo', 'Bar')), FALSE)",
            "SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(dns.answers, _sigma_element -> _sigma_element.name IN ('Foo', 'Bar')), FALSE)",
        ]
    )


def test_array_contains(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: Array Contains
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                scalar:
                    tags|contains: Foo
                struct:
                    dns.answers.name|contains: Foo
                condition:
                    - scalar
                    - struct
        """))
        == [
            r"SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(tags, _sigma_element -> LOWER(_sigma_element) LIKE '%foo%' ESCAPE '\'), FALSE)",
            r"SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(dns.answers, _sigma_element -> LOWER(_sigma_element.name) LIKE '%foo%' ESCAPE '\'), FALSE)",
        ]
    )


def test_array_startswith(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: Array Startswith
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                scalar:
                    tags|startswith: Foo
                struct:
                    dns.answers.name|startswith: Foo
                condition:
                    - scalar
                    - struct
        """))
        == [
            r"SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(tags, _sigma_element -> LOWER(_sigma_element) LIKE 'foo%' ESCAPE '\'), FALSE)",
            r"SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(dns.answers, _sigma_element -> LOWER(_sigma_element.name) LIKE 'foo%' ESCAPE '\'), FALSE)",
        ]
    )


def test_array_endswith(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: Array Endswith
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                scalar:
                    tags|endswith: Foo
                struct:
                    dns.answers.name|endswith: Foo
                condition:
                    - scalar
                    - struct
        """))
        == [
            r"SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(tags, _sigma_element -> LOWER(_sigma_element) LIKE '%foo' ESCAPE '\'), FALSE)",
            r"SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(dns.answers, _sigma_element -> LOWER(_sigma_element.name) LIKE '%foo' ESCAPE '\'), FALSE)",
        ]
    )


def test_array_cased_contains(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: Array Cased Contains
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                scalar:
                    tags|cased|contains: Foo
                struct:
                    dns.answers.name|cased|contains: Foo
                condition:
                    - scalar
                    - struct
        """))
        == [
            r"SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(tags, _sigma_element -> _sigma_element LIKE '%Foo%' ESCAPE '\'), FALSE)",
            r"SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(dns.answers, _sigma_element -> _sigma_element.name LIKE '%Foo%' ESCAPE '\'), FALSE)",
        ]
    )


def test_array_contains_escaped_wildcards(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: Array Contains Escaped Wildcards
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                scalar:
                    tags|contains: 'a%b_c'
                struct:
                    dns.answers.name|contains: 'a%b_c'
                condition:
                    - scalar
                    - struct
        """))
        == [
            r"SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(tags, _sigma_element -> LOWER(_sigma_element) LIKE '%a\%b\_c%' ESCAPE '\'), FALSE)",
            r"SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(dns.answers, _sigma_element -> LOWER(_sigma_element.name) LIKE '%a\%b\_c%' ESCAPE '\'), FALSE)",
        ]
    )


def test_array_regex(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: Array Regex
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                scalar:
                    tags|re: Foo.*bar
                struct:
                    dns.answers.name|re: Foo.*bar
                condition:
                    - scalar
                    - struct
        """))
        == [
            "SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(tags, _sigma_element -> REGEXP_LIKE(_sigma_element, 'Foo.*bar')), FALSE)",
            "SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(dns.answers, _sigma_element -> REGEXP_LIKE(_sigma_element.name, 'Foo.*bar')), FALSE)",
        ]
    )


def test_array_cidr(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: Array CIDR
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                scalar:
                    tags|cidr: 10.0.0.0/8
                struct:
                    dns.answers.name|cidr: 10.0.0.0/8
                condition:
                    - scalar
                    - struct
        """))
        == [
            "SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(tags, _sigma_element -> COALESCE(CONTAINS('10.0.0.0/8', TRY_CAST(_sigma_element AS IPADDRESS)), FALSE)), FALSE)",
            "SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(dns.answers, _sigma_element -> COALESCE(CONTAINS('10.0.0.0/8', TRY_CAST(_sigma_element.name AS IPADDRESS)), FALSE)), FALSE)",
        ]
    )


def test_array_numeric_equality(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: Array Numeric Equality
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                scalar:
                    tags: 42
                struct:
                    dns.answers.name: 42
                condition:
                    - scalar
                    - struct
        """))
        == [
            "SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(tags, _sigma_element -> _sigma_element = 42), FALSE)",
            "SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(dns.answers, _sigma_element -> _sigma_element.name = 42), FALSE)",
        ]
    )


def test_array_numeric_list(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: Array Numeric List
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                scalar:
                    tags:
                        - 1
                        - 2
                struct:
                    dns.answers.name:
                        - 1
                        - 2
                condition:
                    - scalar
                    - struct
        """))
        == [
            "SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(tags, _sigma_element -> _sigma_element IN (1, 2)), FALSE)",
            "SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(dns.answers, _sigma_element -> _sigma_element.name IN (1, 2)), FALSE)",
        ]
    )


def test_array_boolean_equality(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: Array Boolean Equality
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                scalar:
                    tags: true
                struct:
                    dns.answers.name: true
                condition:
                    - scalar
                    - struct
        """))
        == [
            "SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(tags, _sigma_element -> _sigma_element = true), FALSE)",
            "SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(dns.answers, _sigma_element -> _sigma_element.name = true), FALSE)",
        ]
    )


def test_array_numeric_comparison(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: Array Numeric Comparison
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                scalar:
                    tags|gte: 10
                struct:
                    dns.answers.name|gte: 10
                condition:
                    - scalar
                    - struct
        """))
        == [
            "SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(tags, _sigma_element -> _sigma_element >= 10), FALSE)",
            "SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(dns.answers, _sigma_element -> _sigma_element.name >= 10), FALSE)",
        ]
    )


def test_array_all_independent_elements(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: Array All Independent Elements
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                sel:
                    tags|all:
                        - foo
                        - bar
                condition: sel
        """))
        == [
            "SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(tags, _sigma_element -> LOWER(_sigma_element) = 'foo'), FALSE) AND COALESCE(ANY_MATCH(tags, _sigma_element -> LOWER(_sigma_element) = 'bar'), FALSE)"
        ]
    )


def test_array_not(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: Array Negation
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                sel:
                    tags: foo
                condition: not sel
        """))
        == [
            "SELECT * FROM <TABLE> WHERE NOT COALESCE(ANY_MATCH(tags, _sigma_element -> LOWER(_sigma_element) = 'foo'), FALSE)"
        ]
    )


def test_array_members_and_scalar_independent(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: Independent Array Members And Scalar
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                sel:
                    dns.answers.name: foo
                    dns.answers.type: A
                    status: ok
                condition: sel
        """))
        == [
            "SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(dns.answers, _sigma_element -> LOWER(_sigma_element.name) = 'foo'), FALSE) AND COALESCE(ANY_MATCH(dns.answers, _sigma_element -> LOWER(_sigma_element.type) = 'a'), FALSE) AND LOWER(status) = 'ok'"
        ]
    )


def test_array_wildcard_list(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: Array Wildcard List
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                sel:
                    tags|contains:
                        - foo
                        - bar
                condition: sel
        """))
        == [
            r"SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(tags, _sigma_element -> LOWER(_sigma_element) LIKE '%foo%' ESCAPE '\'), FALSE) OR COALESCE(ANY_MATCH(tags, _sigma_element -> LOWER(_sigma_element) LIKE '%bar%' ESCAPE '\'), FALSE)"
        ]
    )


def test_array_level_null(athena_backend: athenaBackend):
    assert athena_backend.convert(SigmaCollection.from_yaml("""
            title: Array Level Null
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                sel:
                    tags: null
                condition: sel
        """)) == ["SELECT * FROM <TABLE> WHERE tags IS NULL"]


def test_array_level_exists(athena_backend: athenaBackend):
    assert athena_backend.convert(SigmaCollection.from_yaml("""
            title: Array Level Exists
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                sel:
                    tags|exists: true
                condition: sel
        """)) == ["SELECT * FROM <TABLE> WHERE tags IS NOT NULL"]


def test_array_level_not_exists(athena_backend: athenaBackend):
    assert athena_backend.convert(SigmaCollection.from_yaml("""
            title: Array Level Not Exists
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                sel:
                    tags|exists: false
                condition: sel
        """)) == ["SELECT * FROM <TABLE> WHERE tags IS NULL"]


def test_array_member_null_unsupported(athena_backend: athenaBackend):
    with pytest.raises(
        NotImplementedError,
        match="Null and existence checks on array members are not supported",
    ):
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: Unsupported Array Member Null
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                sel:
                    dns.answers.name: null
                condition: sel
        """))


def test_array_member_exists_unsupported(athena_backend: athenaBackend):
    with pytest.raises(
        NotImplementedError,
        match="Null and existence checks on array members are not supported",
    ):
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: Unsupported Array Member Exists
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                sel:
                    dns.answers.name|exists: true
                condition: sel
        """))


def test_array_member_not_exists_unsupported(athena_backend: athenaBackend):
    with pytest.raises(
        NotImplementedError,
        match="Null and existence checks on array members are not supported",
    ):
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: Unsupported Array Member Not Exists
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                sel:
                    dns.answers.name|exists: false
                condition: sel
        """))


def test_array_to_scalar_fieldref_unsupported(athena_backend: athenaBackend):
    with pytest.raises(
        NotImplementedError, match="Array field references are not supported"
    ):
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: Unsupported Array To Scalar Field Reference
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                sel:
                    tags|fieldref: status
                condition: sel
        """))


def test_scalar_to_array_fieldref_unsupported(athena_backend: athenaBackend):
    with pytest.raises(
        NotImplementedError, match="Array field references are not supported"
    ):
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: Unsupported Scalar To Array Field Reference
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                sel:
                    status|fieldref: tags
                condition: sel
        """))


def test_array_to_array_fieldref_unsupported(athena_backend: athenaBackend):
    with pytest.raises(
        NotImplementedError, match="Array field references are not supported"
    ):
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: Unsupported Array To Array Field Reference
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                sel:
                    tags|fieldref: dns.answers.name
                condition: sel
        """))


@pytest.mark.parametrize("fields", [42, {}, [""], [" tags"], ["tags", "tags.nested"]])
def test_invalid_array_configuration(fields):
    with pytest.raises(ValueError, match="array_fields"):
        athenaBackend(array_fields=fields)


def test_array_configuration_string():
    backend = athenaBackend(array_fields=" dns.answers, tags ")
    assert (
        backend.convert(SigmaCollection.from_yaml("""
            title: Array Configuration String
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                sel:
                    tags: foo
                condition: sel
        """))
        == [
            "SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(tags, _sigma_element -> LOWER(_sigma_element) = 'foo'), FALSE)"
        ]
    )


def test_unconfigured_fields_unchanged():
    backend = athenaBackend(array_fields=[])
    assert backend.convert(SigmaCollection.from_yaml("""
            title: Unconfigured Fields Unchanged
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                sel:
                    tags: foo
                condition: sel
        """)) == ["SELECT * FROM <TABLE> WHERE LOWER(tags) = 'foo'"]


def test_array_path_boundary(athena_backend: athenaBackend):
    assert athena_backend.convert(SigmaCollection.from_yaml("""
            title: Array Path Boundary
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                sel:
                    tags_extra: foo
                condition: sel
        """)) == ["SELECT * FROM <TABLE> WHERE LOWER(tags_extra) = 'foo'"]


def test_array_field_quoting():
    backend = athenaBackend(array_fields=["dns.answer-list"])
    assert (
        backend.convert(SigmaCollection.from_yaml("""
            title: Array Field Quoting
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                sel:
                    dns.answer-list.host-name: Foo
                condition: sel
        """))
        == [
            """SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(dns."answer-list", _sigma_element -> LOWER(_sigma_element."host-name") = 'foo'), FALSE)"""
        ]
    )


def test_array_lambda_name_collision():
    backend = athenaBackend(array_fields=["_sigma_element.values"])
    assert (
        backend.convert(SigmaCollection.from_yaml("""
            title: Array Lambda Name Collision
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                sel:
                    _sigma_element.values: foo
                condition: sel
        """))
        == [
            "SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(_sigma_element.values, _sigma_element_ -> LOWER(_sigma_element_) = 'foo'), FALSE)"
        ]
    )


def test_array_pipeline_mapping_and_rule_isolation():
    pipeline = ProcessingPipeline.from_yaml("""
    name: Array mapping
    transformations:
      - id: answers_mapping
        type: field_name_mapping
        mapping:
          answers: dns.answers.name
      - id: route53_arrays
        type: set_state
        key: array_fields
        val: [dns.answers]
        rule_conditions:
          - type: logsource
            product: aws
            service: route53
    """)
    backend = athenaBackend(processing_pipeline=pipeline)
    assert (
        backend.convert(SigmaCollection.from_yaml("""
title: Route53
status: test
logsource:
    product: aws
    service: route53
detection:
    sel:
        answers:
            - '127.0.0.1'
            - '0.0.0.0'
    condition: sel
---
title: Other source
status: test
logsource:
    product: aws
    service: cloudtrail
detection:
    sel:
        answers: foo
    condition: sel
"""))
        == [
            "SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(dns.answers, _sigma_element -> LOWER(_sigma_element.name) IN ('127.0.0.1', '0.0.0.0')), FALSE)",
            "SELECT * FROM <TABLE> WHERE LOWER(dns.answers.name) = 'foo'",
        ]
    )


def test_pipeline_overrides_backend_configuration():
    pipeline = ProcessingPipeline.from_yaml("""
    name: Disable arrays
    transformations:
      - id: arrays
        type: set_state
        key: array_fields
        val: []
    """)
    backend = athenaBackend(
        array_fields=["dns.answers", "tags"], processing_pipeline=pipeline
    )
    assert backend.convert(SigmaCollection.from_yaml("""
            title: Pipeline Overrides Array Configuration
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                sel:
                    tags: foo
                condition: sel
        """)) == ["SELECT * FROM <TABLE> WHERE LOWER(tags) = 'foo'"]


def test_invalid_pipeline_array_configuration():
    pipeline = ProcessingPipeline.from_yaml("""
    name: Invalid arrays
    transformations:
      - id: arrays
        type: set_state
        key: array_fields
        val: 42
    """)
    backend = athenaBackend(
        array_fields=["dns.answers", "tags"], processing_pipeline=pipeline
    )
    with pytest.raises(ValueError, match="array_fields"):
        backend.convert(SigmaCollection.from_yaml("""
            title: Invalid Pipeline Array Configuration
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                sel:
                    tags: foo
                condition: sel
        """))


def test_array_boolean_grouping(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: Array Boolean Grouping
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                sel:
                    tags:
                        - foo
                        - bar
                    status: ok
                condition: not sel
        """))
        == [
            "SELECT * FROM <TABLE> WHERE NOT ((COALESCE(ANY_MATCH(tags, _sigma_element -> LOWER(_sigma_element) IN ('foo', 'bar')), FALSE)) AND LOWER(status) = 'ok')"
        ]
    )


def test_array_conversion_does_not_mutate_rule():
    collection = SigmaCollection.from_yaml("""
    title: Repeated Conversion
    status: test
    logsource:
        product: test
    detection:
        sel:
            tags:
                - Foo
                - Bar
        condition: sel
    """)
    backend = athenaBackend(array_fields=["tags"])
    expected = [
        "SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(tags, _sigma_element -> LOWER(_sigma_element) IN ('foo', 'bar')), FALSE)"
    ]
    assert backend.convert(collection) == expected
    assert backend.convert(collection) == expected
    assert athenaBackend().convert(collection) == [
        "SELECT * FROM <TABLE> WHERE LOWER(tags) IN ('foo', 'bar')"
    ]


def test_array_in_after_scalar_wildcard(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: Array IN After Scalar Wildcard
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                sel:
                    status|contains: x
                    tags:
                        - 'a%b'
                        - 'c_d'
                condition: sel
        """))
        == [
            r"SELECT * FROM <TABLE> WHERE LOWER(status) LIKE '%x%' ESCAPE '\' AND (COALESCE(ANY_MATCH(tags, _sigma_element -> LOWER(_sigma_element) IN ('a%b', 'c_d')), FALSE))"
        ]
    )


def test_array_non_octet_cidr(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: Array Non-Octet CIDR
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                sel:
                    tags|cidr: 10.0.0.0/15
                condition: sel
        """))
        == [
            "SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(tags, _sigma_element -> COALESCE(CONTAINS('10.0.0.0/15', TRY_CAST(_sigma_element AS IPADDRESS)), FALSE)), FALSE)"
        ]
    )


def test_array_mixed_case_branches(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: Array Mixed Case Branches
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                sel:
                    tags: foo
                other:
                    tags|cased: Foo
                condition: sel or other
        """))
        == [
            "SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(tags, _sigma_element -> LOWER(_sigma_element) = 'foo'), FALSE) OR COALESCE(ANY_MATCH(tags, _sigma_element -> _sigma_element = 'Foo'), FALSE)"
        ]
    )


def test_array_ipv6_cidr_and_negation(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: Array IPv6 CIDR And Negation
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                scalar:
                    tags|cidr: '2001:db8::/33'
                struct:
                    dns.answers.name|cidr: '2001:db8::/33'
                condition:
                    - scalar
                    - not struct
        """))
        == [
            "SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(tags, _sigma_element -> COALESCE(CONTAINS('2001:db8::/33', TRY_CAST(_sigma_element AS IPADDRESS)), FALSE)), FALSE)",
            "SELECT * FROM <TABLE> WHERE NOT COALESCE(ANY_MATCH(dns.answers, _sigma_element -> COALESCE(CONTAINS('2001:db8::/33', TRY_CAST(_sigma_element.name AS IPADDRESS)), FALSE)), FALSE)",
        ]
    )


def test_array_element_at_interaction():
    backend = athenaBackend(
        array_fields=["unmapped.answers"],
        element_at_fields=["unmapped", "_sigma_element"],
    )
    assert (
        backend.convert(SigmaCollection.from_yaml("""
            title: Map Array
            status: test
            logsource:
                product: test
            detection:
                sel:
                    unmapped.answers.name: foo
                condition: sel
        """))
        == [
            "SELECT * FROM <TABLE> WHERE COALESCE(ANY_MATCH(element_at(unmapped, 'answers'), _sigma_element_ -> LOWER(_sigma_element_.name) = 'foo'), FALSE)"
        ]
    )
