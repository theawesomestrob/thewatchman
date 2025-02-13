from datetime import datetime
from typing import Any
import pytz
from textwrap import wrap
import time
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from prettytable import PrettyTable
from .utils import get_config, get_entity_state, get_entry, is_action
from .logger import _LOGGER
from ..const import (
    CONF_ACTION_NAME,
    CONF_COLUMNS_WIDTH,
    CONF_FRIENDLY_NAMES,
    DOMAIN,
    DEFAULT_HEADER,
    CONF_HEADER,
    HASS_DATA_CHECK_DURATION,
    HASS_DATA_COORDINATOR,
    HASS_DATA_FILES_IGNORED,
    HASS_DATA_FILES_PARSED,
    HASS_DATA_MISSING_ENTITIES,
    HASS_DATA_MISSING_SERVICES,
    HASS_DATA_PARSE_DURATION,
    HASS_DATA_PARSED_ENTITY_LIST,
    HASS_DATA_PARSED_SERVICE_LIST,
    REPORT_ENTRY_TYPE_ENTITY,
    REPORT_ENTRY_TYPE_SERVICE,
)


async def parsing_stats(hass, start_time):
    """separate func for test mocking"""

    def get_timezone(hass):
        return pytz.timezone(hass.config.time_zone)

    timezone = await hass.async_add_executor_job(get_timezone, hass)
    return (
        datetime.now(timezone).strftime("%d %b %Y %H:%M:%S"),
        hass.data[DOMAIN][HASS_DATA_PARSE_DURATION],
        hass.data[DOMAIN][HASS_DATA_CHECK_DURATION],
        time.time() - start_time,
    )


def report_section(
    hass, render, report_type, *, singular, plural, num_total, num_missing
):
    result = []
    if not num_total:
        result = [f"-== No {plural} found in configuration files!"]
    else:
        if num_missing > 0:
            name = singular if num_missing == 1 else plural
            result = [
                f"-== Missing {num_missing} {name} from {num_total} found in your config:"
            ] + render(hass, report_type).splitlines()
        else:
            name = singular if num_missing == 1 else plural
            result = [
                f"-== Congratulations, all {num_total} {name} from your config are available!"
            ]
    return result


async def report(hass, render, chunk_size):
    """generates watchman report either as a table or as a list"""
    if DOMAIN not in hass.data:
        raise HomeAssistantError("No data for report, refresh required.")

    start_time = time.time()
    header = get_config(hass, CONF_HEADER, DEFAULT_HEADER)
    services_missing = hass.data[DOMAIN][HASS_DATA_MISSING_SERVICES]
    service_list = hass.data[DOMAIN][HASS_DATA_PARSED_SERVICE_LIST]
    entities_missing = hass.data[DOMAIN][HASS_DATA_MISSING_ENTITIES]
    entity_list = hass.data[DOMAIN][HASS_DATA_PARSED_ENTITY_LIST]
    files_parsed = hass.data[DOMAIN][HASS_DATA_FILES_PARSED]
    files_ignored = hass.data[DOMAIN][HASS_DATA_FILES_IGNORED]

    report = [header, ""]

    report += report_section(
        hass,
        render,
        REPORT_ENTRY_TYPE_SERVICE,
        singular="action",
        plural="actions",
        num_total=len(service_list),
        num_missing=len(services_missing),
    )

    report.append("")
    report += report_section(
        hass,
        render,
        REPORT_ENTRY_TYPE_ENTITY,
        singular="entity",
        plural="entities",
        num_total=len(entity_list),
        num_missing=len(entities_missing),
    )

    (
        report_datetime,
        parse_duration,
        check_duration,
        render_duration,
    ) = await parsing_stats(hass, start_time)

    report += [
        "",
        f"-== Report created on {report_datetime}",
        f"-== Parsed {files_parsed} files in {parse_duration:.2f}s., ignored {files_ignored} files",
        f"-== Generated in: {render_duration:.2f}s. Validated in: {check_duration:.2f}s.",
        "",
    ]

    report_chunks = []
    if chunk_size > 0:
        report_chunks = split_chunks(report, chunk_size)
    else:
        report_chunks = [report]

    report_chunks = ["\n".join(chunk) for chunk in report_chunks]
    return report_chunks


def split_chunks(lines, chunk_size):
    chunk = []
    total_len = 0
    for line in lines:
        chunk.append(line)
        total_len += len(line)
        if total_len >= chunk_size:
            yield chunk
            chunk = []
            total_len = 0
    if chunk:
        yield chunk


def table_renderer(hass, entry_type):
    """Render ASCII tables in the report"""
    table = PrettyTable()
    columns_width = get_config(hass, CONF_COLUMNS_WIDTH, None)
    columns_width = get_columns_width(columns_width)
    if entry_type == REPORT_ENTRY_TYPE_SERVICE:
        services_missing = hass.data[DOMAIN][HASS_DATA_MISSING_SERVICES]
        service_list = hass.data[DOMAIN][HASS_DATA_PARSED_SERVICE_LIST]
        table.field_names = ["Action ID", "State", "Location"]
        for service in services_missing:
            row = [
                fill(service, columns_width[0]),
                fill("missing", columns_width[1]),
                fill(service_list[service], columns_width[2]),
            ]
            table.add_row(row)
        table.align = "l"
        return table.get_string()
    elif entry_type == REPORT_ENTRY_TYPE_ENTITY:
        entities_missing = hass.data[DOMAIN][HASS_DATA_MISSING_ENTITIES]
        parsed_entity_list = hass.data[DOMAIN][HASS_DATA_PARSED_ENTITY_LIST]
        friendly_names = get_config(hass, CONF_FRIENDLY_NAMES, False)
        header = ["Entity ID", "State", "Location"]
        table.field_names = header
        for entity in entities_missing:
            state, name = get_entity_state(hass, entity, friendly_names)
            label = f"{entity} ({name})" if name else str(entity)
            table.add_row(
                [
                    fill(label, columns_width[0]),
                    fill(state, columns_width[1]),
                    fill(parsed_entity_list[entity], columns_width[2]),
                ]
            )

        table.align = "l"
        return table.get_string()

    else:
        return f"Table render error: unknown entry type: {entry_type}"


def text_renderer(hass, entry_type):
    """Render plain lists in the report"""
    result = ""
    if entry_type == REPORT_ENTRY_TYPE_SERVICE:
        services_missing = hass.data[DOMAIN][HASS_DATA_MISSING_SERVICES]
        service_list = hass.data[DOMAIN][HASS_DATA_PARSED_SERVICE_LIST]
        for service in services_missing:
            result += f"{service} in {fill(service_list[service], 0)}\n"
        return result
    elif entry_type == REPORT_ENTRY_TYPE_ENTITY:
        entities_missing = hass.data[DOMAIN][HASS_DATA_MISSING_ENTITIES]
        entity_list = hass.data[DOMAIN][HASS_DATA_PARSED_ENTITY_LIST]
        friendly_names = get_config(hass, CONF_FRIENDLY_NAMES, False)
        for entity in entities_missing:
            state, name = get_entity_state(hass, entity, friendly_names)
            entity_col = entity if not name else f"{entity} ('{name}')"
            result += f"{entity_col} [{state}] in: {fill(entity_list[entity], 0)}\n"

        return result
    else:
        return f"Text render error: unknown entry type: {entry_type}"


def file_locations(locations):
    return [
        file + ":" + ",".join(str(n) for n in line_numbers)
        for (file, line_numbers) in locations.items()
    ]


def fill(data, width):
    """arrange data by table column width"""
    lines = file_locations(data) if isinstance(data, dict) else [str(data)]

    if width > 0:
        lines = [
            wrapped_line.ljust(width)
            for line in lines
            for wrapped_line in wrap(line, width)
        ]

    return "\n".join(lines)


def get_columns_width(user_width):
    """define width of the report columns"""
    default_width = [30, 7, 60]
    if not user_width:
        return default_width
    try:
        return [7 if user_width[i] < 7 else user_width[i] for i in range(3)]
    except (TypeError, IndexError):
        _LOGGER.error(
            "Invalid configuration for table column widths, default values" " used %s",
            default_width,
        )
    return default_width


async def async_report_to_file(hass, path):
    """save report to a file"""
    report_chunks = await report(hass, table_renderer, chunk_size=0)
    await get_entry(hass).runtime_data.coordinator.async_refresh()

    def write(path):
        with open(path, "w", encoding="utf-8") as report_file:
            for chunk in report_chunks:
                report_file.write(chunk)

    await hass.async_add_executor_job(write, path)
    _LOGGER.debug(f"::async_report_to_file:: Repost saved to {path}")


async def async_report_to_notification(
    hass: HomeAssistant, action_str: str, service_data: dict[str, Any], chunk_size: int
):
    """send report via notification action"""

    if not action_str:
        raise HomeAssistantError(f"Missing `{CONF_ACTION_NAME}` parameter.")

    if action_str and not isinstance(action_str, str):
        raise HomeAssistantError(
            f"`action` parameter should be a string, got {action_str}"
        )

    if not is_action(hass, action_str):
        raise HomeAssistantError(f"{action_str} is not a valid action for notification")

    domain = action_str.split(".")[0]
    action = ".".join(action_str.split(".")[1:])

    data = {} if service_data is None else service_data

    _LOGGER.debug(f"SERVICE_DATA {data}")

    coordinator = hass.data[DOMAIN][HASS_DATA_COORDINATOR]
    await coordinator.async_refresh()
    report_chunks = await report(hass, text_renderer, chunk_size)
    for msg_chunk in report_chunks:
        data["message"] = msg_chunk
        # blocking=True ensures send order
        await hass.services.async_call(domain, action, data, blocking=True)
