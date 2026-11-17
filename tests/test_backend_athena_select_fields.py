import pytest
from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingPipeline

from sigma.backends.athena import athenaBackend


@pytest.fixture
def athena_backend():
    return athenaBackend()


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
                    fieldB: valueB
                condition: sel
            fields:
            - time_dt
            - metadata.uid as event_id
            - actor.us@er.uid as actor_uid
            - element_at(unmapped, 'serviceEventDetails.account_id') as target_account_id
        """
            )
        )
        == [
            """SELECT time_dt, metadata.uid as event_id, actor."us@er".uid as actor_uid, element_at(unmapped, 'serviceEventDetails.account_id') as target_account_id FROM <TABLE> WHERE LOWER(fieldA) = 'valuea' AND LOWER(fieldB) = 'valueb'"""
        ]
    )


def test_map_select_fields_have_stable_aliases():
    backend = athenaBackend(element_at_fields=["labels", "Original"])
    query = backend.convert(SigmaCollection.from_yaml("""
        title: Map field projections
        status: test
        logsource:
            product: test
        detection:
            sel:
                field: value
            condition: sel
        fields:
            - labels.foo
            - labels.bar
            - Original.conn_state
    """))[0]

    assert query == (
        "SELECT element_at(labels, 'foo') AS \"labels.foo\", "
        "element_at(labels, 'bar') AS \"labels.bar\", "
        "element_at(Original, 'conn_state') AS \"Original.conn_state\" "
        "FROM <TABLE> WHERE LOWER(field) = 'value'"
    )


def test_map_select_fields_use_pipeline_mapped_names():
    pipeline = ProcessingPipeline.from_yaml("""
        name: Map field mappings
        transformations:
          - id: map_fields
            type: field_name_mapping
            mapping:
              source: [labels.foo, Original.conn_state]
    """)
    backend = athenaBackend(
        processing_pipeline=pipeline,
        element_at_fields=["labels", "Original"],
    )
    query = backend.convert(SigmaCollection.from_yaml("""
        title: Mapped map field projections
        status: test
        logsource:
            product: test
        detection:
            sel:
                field: value
            condition: sel
        fields:
            - source
    """))[0]

    assert query == (
        "SELECT element_at(labels, 'foo') AS \"labels.foo\", "
        "element_at(Original, 'conn_state') AS \"Original.conn_state\" "
        "FROM <TABLE> WHERE LOWER(field) = 'value'"
    )


def test_map_select_fields_preserve_explicit_aliases():
    backend = athenaBackend(element_at_fields=["labels", "Original"])
    query = backend.convert(SigmaCollection.from_yaml("""
        title: Explicit map aliases
        status: test
        logsource:
            product: test
        detection:
            sel:
                field: value
            condition: sel
        fields:
            - labels.foo as custom_field
            - Original.conn_state AS state
    """))[0]

    assert query == (
        "SELECT element_at(labels, 'foo') as custom_field, "
        "element_at(Original, 'conn_state') AS state "
        "FROM <TABLE> WHERE LOWER(field) = 'value'"
    )


def test_map_select_fields_escape_dotted_keys_and_quotes():
    backend = athenaBackend(element_at_fields=["labels"])
    query = backend.convert(SigmaCollection.from_yaml(r"""
        title: Escaped map field projections
        status: test
        logsource:
            product: test
        detection:
            sel:
                field: value
            condition: sel
        fields:
            - 'labels.foo\.bar'
            - "labels.o'brien"
            - 'labels.name"tag'
    """))[0]

    assert query == (
        "SELECT element_at(labels, 'foo.bar') AS \"labels.foo.bar\", "
        """element_at(labels, 'o''brien') AS "labels.o'brien", """
        "element_at(labels, 'name\"tag') AS \"labels.name\"\"tag\" "
        "FROM <TABLE> WHERE LOWER(field) = 'value'"
    )


def test_map_select_fields_leave_predicates_columns_and_wildcards_unchanged():
    backend = athenaBackend(element_at_fields=["labels"])
    query = backend.convert(SigmaCollection.from_yaml("""
        title: Map and ordinary projections
        status: test
        logsource:
            product: test
        detection:
            sel:
                labels.foo: value
            condition: sel
        fields:
            - labels.foo
            - ordinary_column
    """))[0]
    wildcard_query = backend.convert(SigmaCollection.from_yaml("""
        title: Wildcard projection
        status: test
        logsource:
            product: test
        detection:
            sel:
                field: value
            condition: sel
    """))[0]

    assert query == (
        "SELECT element_at(labels, 'foo') AS \"labels.foo\", ordinary_column "
        "FROM <TABLE> WHERE LOWER(element_at(labels, 'foo')) = 'value'"
    )
    assert wildcard_query == "SELECT * FROM <TABLE> WHERE LOWER(field) = 'value'"
