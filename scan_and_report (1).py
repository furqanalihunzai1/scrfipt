#!/usr/bin/env python3
"""
Script for scanning a host with OpenVAS and exporting the report.
"""
import sys
import datetime
import time
import argparse

from os.path import exists
from base64 import b64decode
from pathlib import Path
from gvm.connections import UnixSocketConnection
from gvm.errors import GvmError
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform


# Full and fast scan config
SCAN_CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"

# OpenVAS Default scanner
OPENVAS_SCANNER_ID = "08b69003-5fc2-4037-a479-93b440211c73"

# PDF report format ID
PDF_REPORT_FORMAT_ID = "c402cc3e-b531-11e1-9163-406186ea4fc5"


def create_target(gmp, host, ports_id):
    """
    Create a target to scan.
    """
    name = f"Suspect Host {host} {str(datetime.datetime.now())}"

    response = gmp.create_target(
        name=name, hosts=[host], port_list_id=ports_id)
    return response.get("id")


def create_task(gmp, ipaddress, target_id, scan_config_id, scanner_id):
    """
    Create a scan task.
    """
    name = f"Scan Suspect Host {ipaddress}"
    response = gmp.create_task(
        name=name,
        config_id=scan_config_id,
        target_id=target_id,
        scanner_id=scanner_id,
    )
    return response.get("id")


def start_task(gmp, task_id):
    """
    Start a created task.
    """
    response = gmp.start_task(task_id)
    # the response is
    # <start_task_response><report_id>id</report_id></start_task_response>
    return response[0].text


def wait_for_report(gmp, task_id):
    """
    Continously check if the report for the given task is available and return
    the task id.
    """
    task = gmp.get_task(task_id)
    last_report_id = task.xpath("task/last_report/report/@id")

    print("Waiting for report", end=" ", flush=True)
    while len(last_report_id) == 0:
        task = gmp.get_task(task_id)
        last_report_id = task.xpath("task/last_report/report/@id")
        time.sleep(30)
        print(".", end="", flush=True)

    print("")


def export_report(gmp, report_id, target):
    """
    Export the report as pdf.
    """

    response = gmp.get_report(
        report_id=report_id, report_format_id=PDF_REPORT_FORMAT_ID
    )

    report_element = response.find("report")
    # get the full content of the report element
    content = report_element.find("report_format").tail

    if not content:
        sys.exit(
            "Requested report is empty. Either the report does not contain any"
            " results or the necessary tools for creating the report are "
            "not installed.",
        )

    # convert content to 8-bit ASCII bytes
    binary_base64_encoded_pdf = content.encode("ascii")

    # decode base64
    binary_pdf = b64decode(binary_base64_encoded_pdf)

    pdf_filename = f"{target}_{str(datetime.datetime.now())}.pdf"
    # write to file and support ~ in filename path
    pdf_path = Path(pdf_filename).expanduser()

    pdf_path.write_bytes(binary_pdf)

    print("Done. PDF created: " + str(pdf_path))


def main():
    """
    Main function
    """
    all_args = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
        Example usage: 
        scan_and_report.py -h\n
        scan_and_report.py -u admin -p 12345 -t 127.0.0.1 -l 4a4717fe-57d2-11e1-9a26-406186ea4fc5w\n
        scan_and_report.py -u admin -p 12345 -t 10.0.2.15 -l 4a4717fe-57d2-11e1-9a26-406186ea4fc5w -s /run/gvmd/gvmd.sock\n
        """,
    )
    all_args.add_argument("-u", "--username",
                          required=True, help="openVAS Username")
    all_args.add_argument("-p", "--password",
                          required=True, help="openVAS Password")
    all_args.add_argument(
        "-s",
        "--socket",
        default="/run/gvmd/gvmd.sock",
        required=False,
        help="openVAS socket path, default:/run/gvmd/gvmd.sock ",
    )
    all_args.add_argument("-t", "--target", required=True,
                          help="target host IP")
    all_args.add_argument(
        "-l", "--ports-id", required=True, help="openVAS id of port list"
    )
    args = all_args.parse_args()

    if not exists(args.socket):
        sys.exit(
            f'The socket file "{args.socket}" does not exist. Is openVAS running? '
        )

    target = args.target

    connection = UnixSocketConnection(path=args.socket)
    transform = EtreeCheckCommandTransform()
    try:

        with Gmp(connection=connection, transform=transform) as gmp:
            gmp.authenticate(args.username, args.password)

            target_id = create_target(gmp, host=target, ports_id=args.ports_id)

            task_id = create_task(
                gmp,
                args.target,
                target_id,
                SCAN_CONFIG_ID,
                OPENVAS_SCANNER_ID,
            )

            report_id = start_task(gmp, task_id)
            print("Task created.")

            wait_for_report(gmp, task_id)

            export_report(gmp, report_id, target)

    except GvmError as err:
        print("An error occurred", err, file=sys.stderr)


if __name__ == "__main__":
    main()
