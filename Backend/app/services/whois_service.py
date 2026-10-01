from __future__ import annotations

from typing import Any

import httpx

from app.providers.rdap import RDAPProvider
from app.schemas.response import (
    RDAPEvent,
    RDAPNameserver,
    WhoisResult,
)


class WhoisService:
    """
    WHOIS / RDAP business service.

    RDAP is the actual data source.

    This service converts provider-specific RDAP JSON into
    a stable PhishGuard schema.
    """

    SOURCE_NAME = "RDAP"

    def __init__(
        self,
        provider: RDAPProvider | None = None,
    ) -> None:

        self.provider = provider

    # =====================================================
    # Helpers
    # =====================================================

    @staticmethod
    def _safe_string(
        value: Any,
    ) -> str | None:

        if value is None:
            return None

        value = str(value).strip()

        return value or None

    @staticmethod
    def _find_vcard_value(
        entity: dict[str, Any],
        property_name: str,
    ) -> str | None:
        """
        Extract a simple textual vCard property.

        RDAP entity names and organizations are represented
        through jCard structures.
        """

        vcard_array = entity.get(
            "vcardArray"
        )

        if not isinstance(
            vcard_array,
            list,
        ):

            return None

        if len(vcard_array) < 2:
            return None

        properties = vcard_array[1]

        if not isinstance(
            properties,
            list,
        ):

            return None

        for item in properties:

            if not isinstance(
                item,
                list,
            ):

                continue

            if len(item) < 4:
                continue

            name = item[0]

            if name != property_name:
                continue

            value = item[3]

            if isinstance(
                value,
                str,
            ):

                return value.strip() or None

            return None

        return None

    @classmethod
    def _entity_roles(
        cls,
        entity: dict[str, Any],
    ) -> list[str]:

        roles = entity.get(
            "roles"
        )

        if not isinstance(
            roles,
            list,
        ):

            return []

        return [
            str(role).lower()
            for role in roles
            if isinstance(
                role,
                str,
            )
        ]

    @classmethod
    def _get_entity_name(
        cls,
        entity: dict[str, Any],
    ) -> str | None:

        return (
            cls._find_vcard_value(
                entity,
                "fn",
            )
            or cls._find_vcard_value(
                entity,
                "org",
            )
        )

    @classmethod
    def _find_entity(
        cls,
        entities: list[Any],
        role: str,
    ) -> dict[str, Any] | None:

        for entity in entities:

            if not isinstance(
                entity,
                dict,
            ):

                continue

            roles = cls._entity_roles(
                entity
            )

            if role.lower() in roles:

                return entity

        return None

    @staticmethod
    def _event_date(
        events: list[dict[str, Any]],
        actions: set[str],
    ) -> str | None:

        for event in events:

            if not isinstance(
                event,
                dict,
            ):

                continue

            action = event.get(
                "eventAction"
            )

            if action not in actions:
                continue

            date = event.get(
                "eventDate"
            )

            if isinstance(
                date,
                str,
            ):

                return date

        return None

    @staticmethod
    def _parse_events(
        events: list[Any],
    ) -> list[RDAPEvent]:

        parsed: list[RDAPEvent] = []

        for event in events:

            if not isinstance(
                event,
                dict,
            ):

                continue

            action = event.get(
                "eventAction"
            )

            if not isinstance(
                action,
                str,
            ):

                continue

            date = event.get(
                "eventDate"
            )

            if not isinstance(
                date,
                str,
            ):

                date = None

            parsed.append(
                RDAPEvent(
                    action=action,
                    date=date,
                )
            )

        return parsed

    @staticmethod
    def _parse_nameservers(
        data: dict[str, Any],
    ) -> list[RDAPNameserver]:

        nameservers = data.get(
            "nameservers",
            [],
        )

        if not isinstance(
            nameservers,
            list,
        ):

            return []

        result: list[RDAPNameserver] = []

        for nameserver in nameservers:

            if not isinstance(
                nameserver,
                dict,
            ):

                continue

            hostname = (
                nameserver.get(
                    "ldhName"
                )
                or nameserver.get(
                    "unicodeName"
                )
            )

            if not isinstance(
                hostname,
                str,
            ):

                continue

            ipv4 = nameserver.get(
                "ipAddresses",
                {},
            )

            ipv4_values = []
            ipv6_values = []

            if isinstance(
                ipv4,
                dict,
            ):

                v4 = ipv4.get(
                    "v4",
                    [],
                )

                v6 = ipv4.get(
                    "v6",
                    [],
                )

                if isinstance(
                    v4,
                    list,
                ):

                    ipv4_values = [
                        str(value)
                        for value in v4
                        if isinstance(
                            value,
                            str,
                        )
                    ]

                if isinstance(
                    v6,
                    list,
                ):

                    ipv6_values = [
                        str(value)
                        for value in v6
                        if isinstance(
                            value,
                            str,
                        )
                    ]

            result.append(
                RDAPNameserver(
                    hostname=hostname,
                    ipv4=ipv4_values,
                    ipv6=ipv6_values,
                )
            )

        return result

    # =====================================================
    # Normalize raw RDAP
    # =====================================================

    def _normalize(
        self,
        domain: str,
        provider_result: dict[str, Any],
    ) -> WhoisResult:

        if not provider_result.get(
            "success",
            False,
        ):

            return WhoisResult(
                domain=domain,
                status=provider_result.get(
                    "status",
                    "error",
                ),
                source=self.SOURCE_NAME,
                rdap_server=provider_result.get(
                    "rdap_server"
                ),
                error=provider_result.get(
                    "error",
                    "RDAP lookup failed.",
                ),
            )

        data = provider_result.get(
            "data",
            {},
        )

        if not isinstance(
            data,
            dict,
        ):

            return WhoisResult(
                domain=domain,
                status="invalid_response",
                source=self.SOURCE_NAME,
                rdap_server=provider_result.get(
                    "rdap_server"
                ),
                error=(
                    "RDAP data was not a JSON object."
                ),
            )

        entities = data.get(
            "entities",
            [],
        )

        if not isinstance(
            entities,
            list,
        ):

            entities = []

        registrar = self._find_entity(
            entities,
            "registrar",
        )

        administrative_entity = (
            self._find_entity(
                entities,
                "administrative",
            )
        )

        events = data.get(
            "events",
            [],
        )

        if not isinstance(
            events,
            list,
        ):

            events = []

        parsed_events = (
            self._parse_events(
                events
            )
        )

        registration_date = (
            self._event_date(
                events,
                {
                    "registration",
                    "reregistration",
                },
            )
        )

        expiration_date = (
            self._event_date(
                events,
                {
                    "expiration",
                    "expiry",
                },
            )
        )

        last_updated_date = (
            self._event_date(
                events,
                {
                    "last changed",
                    "last update of rdap database",
                    "last update",
                    "last changed",
                },
            )
        )

        registrar_name = None

        registrar_id = None

        if registrar:

            registrar_name = (
                self._get_entity_name(
                    registrar
                )
            )

            registrar_id = (
                self._safe_string(
                    registrar.get(
                        "handle"
                    )
                )
            )

        # -------------------------------------------------
        # Some registries expose registry information in
        # rdapConformance / remarks / links instead of a
        # consistent entity role. Keep this conservative.
        # -------------------------------------------------

        registry_entity = self._find_entity(
            entities,
            "registry",
        )

        registry_name = None

        registry_id = None

        if registry_entity:

            registry_name = (
                self._get_entity_name(
                    registry_entity
                )
            )

            registry_id = (
                self._safe_string(
                    registry_entity.get(
                        "handle"
                    )
                )
            )

        statuses = data.get(
            "status",
            [],
        )

        if not isinstance(
            statuses,
            list,
        ):

            statuses = []

        domain_status = [
            str(value)
            for value in statuses
            if isinstance(
                value,
                str,
            )
        ]

        # -------------------------------------------------
        # DNSSEC
        # -------------------------------------------------

        secure_dns = data.get(
            "secureDNS"
        )

        dnssec = None

        if isinstance(
            secure_dns,
            dict,
        ):

            delegation_signed = (
                secure_dns.get(
                    "delegationSigned"
                )
            )

            if delegation_signed is True:

                dnssec = "signed"

            elif delegation_signed is False:

                dnssec = "unsigned"

        # -------------------------------------------------
        # Redaction detection
        # -------------------------------------------------

        redacted = bool(
            data.get(
                "redacted",
                False,
            )
        )

        remarks = data.get(
            "remarks",
            [],
        )

        if isinstance(
            remarks,
            list,
        ):

            for remark in remarks:

                if not isinstance(
                    remark,
                    dict,
                ):

                    continue

                title = str(
                    remark.get(
                        "title",
                        "",
                    )
                ).lower()

                description = str(
                    remark.get(
                        "description",
                        "",
                    )
                ).lower()

                combined = (
                    title
                    + " "
                    + description
                )

                if (
                    "redact" in combined
                    or "privacy" in combined
                ):

                    redacted = True

        return WhoisResult(
            domain=domain,

            status="success",

            source=self.SOURCE_NAME,

            rdap_server=provider_result.get(
                "rdap_server"
            ),

            registration_date=registration_date,

            expiration_date=expiration_date,

            last_updated_date=last_updated_date,

            events=parsed_events,

            registrar_name=registrar_name,

            registrar_id=registrar_id,

            registry_name=registry_name,

            registry_id=registry_id,

            domain_status=domain_status,

            nameservers=self._parse_nameservers(
                data
            ),

            dnssec=dnssec,

            redacted=redacted,

            error=None,
        )

    # =====================================================
    # Public lookup
    # =====================================================

    async def lookup(
        self,
        domain: str | None,
    ) -> WhoisResult:

        if not domain:

            return WhoisResult(
                domain="",
                status="not_applicable",
                source=None,
                error=(
                    "No registrable domain is available "
                    "for WHOIS/RDAP lookup."
                ),
            )

        domain = domain.strip().lower().rstrip(".")

        if not domain:

            return WhoisResult(
                domain="",
                status="not_applicable",
                source=None,
                error=(
                    "Domain is empty."
                ),
            )

        # -------------------------------------------------
        # Provider is created lazily so this service remains
        # easy to unit test.
        # -------------------------------------------------

        timeout = httpx.Timeout(
            timeout=8.0
        )

        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
        ) as client:

            provider = self.provider

            if provider is None:

                provider = RDAPProvider(
                    client
                )

            try:

                provider_result = (
                    await provider.lookup(
                        domain
                    )
                )

            except httpx.TimeoutException:

                return WhoisResult(
                    domain=domain,
                    status="timeout",
                    source=self.SOURCE_NAME,
                    error=(
                        "WHOIS/RDAP lookup timed out."
                    ),
                )

            except httpx.RequestError as exc:

                return WhoisResult(
                    domain=domain,
                    status="error",
                    source=self.SOURCE_NAME,
                    error=(
                        "Network error during "
                        "WHOIS/RDAP lookup: "
                        f"{type(exc).__name__}"
                    ),
                )

            except Exception as exc:

                return WhoisResult(
                    domain=domain,
                    status="error",
                    source=self.SOURCE_NAME,
                    error=(
                        "Unexpected WHOIS/RDAP error: "
                        f"{type(exc).__name__}"
                    ),
                )

        return self._normalize(
            domain,
            provider_result,
        )