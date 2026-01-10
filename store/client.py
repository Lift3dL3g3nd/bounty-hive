from typing import Protocol


class StoreClient(Protocol):
    """
    Store-facing contract used by the engine and audit layers.

    This interface MUST NOT:
    - perform billing
    - expose secrets
    - initiate network access
    - leak implementation details

    Implementations are provided by the store layer only.
    """

    def verify_entitlement(self, entitlement_id: str) -> bool:
        """
        Verify that an entitlement is valid and active.

        Args:
            entitlement_id: Opaque entitlement identifier issued by the Store

        Returns:
            True if the entitlement is valid and active.
            False otherwise.
        """
        ...
