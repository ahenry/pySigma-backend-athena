import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError

from sigma.backends.athena import athenaBackend


@pytest.fixture
def athena_backend():
    return athenaBackend(element_at_fields=["unmapped"])


def test_athena_and_expression(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: value_B
                condition: sel
        """
            )
        )
        == [
            "SELECT * FROM <TABLE> WHERE LOWER(fieldA) = 'valuea' AND LOWER(fieldB) = 'value_b'"
        ]
    )


def test_athena_or_expression(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """
            )
        )
        == [
            "SELECT * FROM <TABLE> WHERE LOWER(fieldA) = 'valuea' OR LOWER(fieldB) = 'valueb'"
        ]
    )


def test_athena_and_or_expression(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB|cased:
                        - valueB1
                        - valueB2
                condition: sel
        """
            )
        )
        == [
            "SELECT * FROM <TABLE> WHERE (LOWER(fieldA) IN ('valuea1', 'valuea2')) AND (fieldB IN ('valueB1', 'valueB2'))"
        ]
    )


def test_athena_or_and_expression(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """
            )
        )
        == [
            "SELECT * FROM <TABLE> WHERE LOWER(fieldA) = 'valuea1' AND LOWER(fieldB) = 'valueb1' OR LOWER(fieldA) = 'valuea2' AND LOWER(fieldB) = 'valueb2'"
        ]
    )
    """
    Athena will interpret it as:
        WHERE (LOWER(fieldA) = 'valuea1' AND LOWER(fieldB) = 'valueb1') OR (LOWER(fieldA) = 'valuea2' AND LOWER(fieldB) = 'valueb2'")
    """


def test_athena_in_expression(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                        - "*valueD"
                condition: sel
        """
            )
        )
        == [
            r"SELECT * FROM <TABLE> WHERE LOWER(fieldA) = 'valuea' OR LOWER(fieldA) = 'valueb' OR LOWER(fieldA) LIKE 'valuec%' ESCAPE '\' OR LOWER(fieldA) LIKE '%valued' ESCAPE '\'"
        ]
    )


def test_athena_regex_query(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: Foo.*bar
                    fieldB: foo
                condition: sel
        """
            )
        )
        == [
            "SELECT * FROM <TABLE> WHERE REGEXP_LIKE(fieldA, 'Foo.*bar') AND LOWER(fieldB) = 'foo'"
        ]
    )


def test_athena_cidr_query(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """
            )
        )
        == [
            "SELECT * FROM <TABLE> WHERE COALESCE(CONTAINS('192.168.0.0/16', TRY_CAST(field AS IPADDRESS)), FALSE)"
        ]
    )


def test_athena_cidr_prefixes(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: CIDR Prefix Lengths
            status: test
            logsource:
                product: test_product
            detection:
                non_octet:
                    address|cidr: 192.168.0.0/17
                host:
                    address|cidr: 192.168.0.1/32
                default_route:
                    address|cidr: 0.0.0.0/0
                ipv6:
                    address|cidr: '2001:db8::/33'
                ipv6_host:
                    address|cidr: '2001:db8::1/128'
                ipv6_default_route:
                    address|cidr: '::/0'
                condition:
                    - non_octet
                    - host
                    - default_route
                    - ipv6
                    - ipv6_host
                    - ipv6_default_route
        """))
        == [
            "SELECT * FROM <TABLE> WHERE COALESCE(CONTAINS('192.168.0.0/17', TRY_CAST(address AS IPADDRESS)), FALSE)",
            "SELECT * FROM <TABLE> WHERE COALESCE(CONTAINS('192.168.0.1/32', TRY_CAST(address AS IPADDRESS)), FALSE)",
            "SELECT * FROM <TABLE> WHERE COALESCE(CONTAINS('0.0.0.0/0', TRY_CAST(address AS IPADDRESS)), FALSE)",
            "SELECT * FROM <TABLE> WHERE COALESCE(CONTAINS('2001:db8::/33', TRY_CAST(address AS IPADDRESS)), FALSE)",
            "SELECT * FROM <TABLE> WHERE COALESCE(CONTAINS('2001:db8::1/128', TRY_CAST(address AS IPADDRESS)), FALSE)",
            "SELECT * FROM <TABLE> WHERE COALESCE(CONTAINS('::/0', TRY_CAST(address AS IPADDRESS)), FALSE)",
        ]
    )


def test_athena_cidr_quoted_and_map_fields(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: CIDR Quoted And Map Fields
            status: test
            logsource:
                product: test_product
            detection:
                quoted:
                    source.ip-address|cidr: 192.168.0.0/25
                mapped:
                    unmapped.source_ip|cidr: 192.168.0.0/25
                condition:
                    - quoted
                    - mapped
        """))
        == [
            """SELECT * FROM <TABLE> WHERE COALESCE(CONTAINS('192.168.0.0/25', TRY_CAST(source."ip-address" AS IPADDRESS)), FALSE)""",
            "SELECT * FROM <TABLE> WHERE COALESCE(CONTAINS('192.168.0.0/25', TRY_CAST(element_at(unmapped, 'source_ip') AS IPADDRESS)), FALSE)",
        ]
    )


def test_athena_cidr_list_and_negation(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(SigmaCollection.from_yaml("""
            title: CIDR List And Negation
            status: test
            logsource:
                product: test_product
            detection:
                sel:
                    address|cidr:
                        - 192.168.0.0/25
                        - '2001:db8::/33'
                condition:
                    - sel
                    - not sel
        """))
        == [
            "SELECT * FROM <TABLE> WHERE COALESCE(CONTAINS('192.168.0.0/25', TRY_CAST(address AS IPADDRESS)), FALSE) OR COALESCE(CONTAINS('2001:db8::/33', TRY_CAST(address AS IPADDRESS)), FALSE)",
            "SELECT * FROM <TABLE> WHERE NOT (COALESCE(CONTAINS('192.168.0.0/25', TRY_CAST(address AS IPADDRESS)), FALSE) OR COALESCE(CONTAINS('2001:db8::/33', TRY_CAST(address AS IPADDRESS)), FALSE))",
        ]
    )


def test_athena_field_name_with_whitespace(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field name: value
                condition: sel
        """
            )
        )
        == ["""SELECT * FROM <TABLE> WHERE LOWER("field name") = 'value'"""]
    )


def test_athena_single_wildcard(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test Single Wildcard
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: val?e
                condition: sel
        """
            )
        )
        == [r"SELECT * FROM <TABLE> WHERE LOWER(fieldA) LIKE 'val_e' ESCAPE '\'"]
    )


def test_athena_escaped_wildcard(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test Escaped Wildcard
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: val\\*e
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE> WHERE LOWER(fieldA) = 'val*e'"]
    )
    # The `*` is interpreted literally; in Athena the * is not treated as a wildcard in LIKE or ILIKE.


def test_athena_contains_percent(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test Contains Modifier
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|contains: sub%String
                condition: sel
        """
            )
        )
        == [
            r"SELECT * FROM <TABLE> WHERE LOWER(fieldA) LIKE '%sub\%string%' ESCAPE '\'"
        ]
    )


def test_athena_contains_modifier(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test Contains Modifier
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|contains: sub_String
                condition: sel
        """
            )
        )
        == [
            r"SELECT * FROM <TABLE> WHERE LOWER(fieldA) LIKE '%sub\_string%' ESCAPE '\'"
        ]
    )


def test_athena_startswith_modifier(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test StartsWith Modifier
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|startswith: Prefix
                condition: sel
        """
            )
        )
        == [r"SELECT * FROM <TABLE> WHERE LOWER(fieldA) LIKE 'prefix%' ESCAPE '\'"]
    )


def test_athena_endswith_modifier(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test EndsWith Modifier
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|endswith: Suffix
                condition: sel
        """
            )
        )
        == [r"SELECT * FROM <TABLE> WHERE LOWER(fieldA) LIKE '%suffix' ESCAPE '\'"]
    )


def test_athena_all_modifier(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test All Modifier
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|all:
                        - value1
                        - value2
                condition: sel
        """
            )
        )
        == [
            "SELECT * FROM <TABLE> WHERE LOWER(fieldA) = 'value1' AND LOWER(fieldA) = 'value2'"
        ]
    )


def test_athena_contains_all_modifier(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test All Modifier
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|contains|all:
                        - value1
                        - value2
                condition: sel
        """
            )
        )
        == [
            r"SELECT * FROM <TABLE> WHERE LOWER(fieldA) LIKE '%value1%' ESCAPE '\' AND LOWER(fieldA) LIKE '%value2%' ESCAPE '\'"
        ]
    )


def test_athena_not_condition(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test Not Condition
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                condition: not sel
        """
            )
        )
        == ["SELECT * FROM <TABLE> WHERE NOT LOWER(fieldA) = 'valuea'"]
    )


def test_athena_nested_condition(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test Nested Condition
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: sel1 and not sel2
        """
            )
        )
        == [
            "SELECT * FROM <TABLE> WHERE LOWER(fieldA) = 'valuea' AND NOT LOWER(fieldB) = 'valueb'"
        ]
    )


def test_athena_null_check(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test Null Check
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: null
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE> WHERE fieldA IS NULL"]
    )


def test_athena_keyword_search(athena_backend: athenaBackend):
    # We don't support keywords
    with pytest.raises(NotImplementedError) as exc_info:
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test Keyword Search
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    keywords:
                        - suspicious
                    condition: keywords
            """
            )
        )


def test_athena_complex_combination(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test Complex Combination
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA|re: Foo.*bar
                    fieldB|contains: baz
                sel2:
                    fieldC|cidr: 10.0.0.0/8
                    fieldD|endswith: suffix
                condition: sel1 or sel2
        """
            )
        )
        == [
            r"SELECT * FROM <TABLE> WHERE REGEXP_LIKE(fieldA, 'Foo.*bar') AND LOWER(fieldB) LIKE '%baz%' ESCAPE '\' OR COALESCE(CONTAINS('10.0.0.0/8', TRY_CAST(fieldC AS IPADDRESS)), FALSE) AND LOWER(fieldD) LIKE '%suffix' ESCAPE '\'"
        ]
    )


def test_athena_special_characters_in_field_name(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test Special Characters in Field Name
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field@name: value
                condition: sel
        """
            )
        )
        == ["""SELECT * FROM <TABLE> WHERE LOWER("field@name") = 'value'"""]
    )


def test_athena_dots_in_field_name(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test Special Characters in Field Name
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    actor.user.uid: Value
                condition: sel
        """
            )
        )
        == ["""SELECT * FROM <TABLE> WHERE LOWER(actor.user.uid) = 'value'"""]
    )


def test_athena_special_characters_dots_in_field_name(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test Special Characters in Field Name
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    actor.us@er.uid: Value
                    actor.user\\.uid: Value
                condition: sel
        """
            )
        )
        == [
            """SELECT * FROM <TABLE> WHERE LOWER(actor."us@er".uid) = 'value' AND LOWER(actor."user.uid") = 'value'"""
        ]
    )


def test_athena_element_at_in_field_name(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test Special Characters in Field Name
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    # We've set 'unmapped' in 'element_at_fields' for the tests.
                    unmapped.serviceEventDetails.account_id: Value
                condition: sel
        """
            )
        )
        == [
            """SELECT * FROM <TABLE> WHERE LOWER(element_at(unmapped, 'serviceEventDetails.account_id')) = 'value'"""
        ]
    )


def test_athena_empty_value(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test Empty Value
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: ''
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE> WHERE LOWER(fieldA) = ''"]
    )


def test_athena_cased_modifier(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test Cased Modifier
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|cased: ValueA
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE> WHERE fieldA = 'ValueA'"]
    )


def test_athena_in_expression_cased_modifier(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|cased:
                        - valueA
                        - valueB
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE> WHERE fieldA IN ('valueA', 'valueB')"]
    )


def test_athena_exists_modifier(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test Exists Modifier
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|exists: true
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE> WHERE fieldA IS NOT NULL"]
    )


def test_athena_not_exists_modifier(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test Not Exists Modifier
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|exists: false
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE> WHERE fieldA IS NULL"]
    )


def test_athena_fieldref_modifier(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test Fieldref Modifier
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|fieldref: fieldB
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE> WHERE LOWER(fieldA) = LOWER(fieldB)"]
    )


def test_athena_numeric_greater_than(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test Numeric Greater Than
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|gt: 100
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE> WHERE fieldA > 100"]
    )


def test_athena_numeric_less_than_or_equal(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test Numeric Less Than or Equal
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|lte: 50
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE> WHERE fieldA <= 50"]
    )


def test_athena_numeric_equal(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test Numeric Equal
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: 42
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE> WHERE fieldA = 42"]
    )


def test_athena_combined_cased_and_numeric(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test Combined Cased and Numeric
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|cased: ValueA
                    fieldB|gte: 200
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE> WHERE fieldA = 'ValueA' AND fieldB >= 200"]
    )


def test_athena_exists_and_fieldref(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test Exists and Fieldref
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA|exists: true
                sel2:
                    fieldB|fieldref: fieldC
                condition: sel1 and sel2
        """
            )
        )
        == [
            "SELECT * FROM <TABLE> WHERE fieldA IS NOT NULL AND LOWER(fieldB) = LOWER(fieldC)"
        ]
    )


def test_athena_numeric_range_and_cased(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test Numeric Range and Cased
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|gt: 10
                    fieldA|lt: 100
                    fieldB|cased: ExactValue
                condition: sel
        """
            )
        )
        == [
            "SELECT * FROM <TABLE> WHERE fieldA > 10 AND fieldA < 100 AND fieldB = 'ExactValue'"
        ]
    )
