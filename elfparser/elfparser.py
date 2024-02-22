import re
import subprocess

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection


def get_all_strings(filepath):
    cmd = ["strings", filepath]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.stdout.split("\n")


def ending_in_number(s: str):
    if s == "":
        return False
    if s[-1] == ".":
        s = s[:-1]
    if s == "":
        return False
    if s[-1].isdigit():
        return True
    return False


def valid_ip_adjacency(ip, ss) -> bool:
    if not ss:
        return True

    for s in ss:
        i = s.index(ip)
        if ending_in_number(s[:i]):
            continue
        if ending_in_number(s[i + len(ip) :][::-1]):
            continue
        return True
    return False


class ELFPARSER(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config)

    def start(self):
        self.log.debug("Starting ELFPARSER")
        self.header_line = re.compile(".* - Score: (\\d+) \\[Family: (.*)\\]")

    def execute(self, request: ServiceRequest):
        request.result = Result()
        self.file_res = request.result
        self.request = request

        cmd = ["./elfparser-cli-1.4.0", "-c", "-r", "-f", request.file_path]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0 or len(proc.stderr) != 0:
            res = ResultSection("This file looks like an ELF but failed loading.")
            if len(proc.stdout) > 0:
                sub_res = ResultSection("Output")
                sub_res.add_line(proc.stdout)
                res.add_subsection(sub_res)
            if len(proc.stderr) > 0:
                sub_res = ResultSection("Error")
                sub_res.add_line(proc.stderr)
                res.add_subsection(sub_res)
            self.file_res.add_section(res)
            return

        output = proc.stdout.split("\n")
        m = self.header_line.match(output[0])
        score = m.group(1)
        family = m.group(2)
        res = ResultSection("Summary")
        res.add_line(f"Total score: {score}")
        if family != "Undetermined":
            res.add_line(f"Familiy: {family}")
        self.file_res.add_section(res)

        currentline = 2
        res = None
        for line in output[currentline:]:
            currentline += 1
            if line == "---- Detected Capabilities ----":
                break
            if res is None:
                res = ResultSection("Scores")
            res.add_line(line)
        if res is not None:
            self.file_res.add_section(res)

        res = None
        sub_res = None
        all_strings_in_file = None
        for line in output[currentline:]:
            if line == "":
                continue
            if res is None:
                res = ResultSection("Capabilities")
            if line.startswith("\t\t"):
                if sub_res.title_text == "IP Addresses":
                    if all_strings_in_file is None:
                        all_strings_in_file = get_all_strings(request.file_path)
                    ip = line[2:].strip()
                    if ip in all_strings_in_file:
                        sub_res.add_line(ip)
                        sub_res.add_tag("network.static.ip", ip)
                    else:
                        containing_ip = [x for x in filter(lambda x: ip in x, all_strings_in_file)]
                        if valid_ip_adjacency(ip, containing_ip):
                            sub_res.add_line(ip)
                            sub_res.add_tag("network.static.ip", ip)
                else:
                    sub_res.add_line(line[2:])
            elif line.startswith("\t"):
                if sub_res is not None and sub_res.body:
                    res.add_subsection(sub_res)
                sub_res = ResultSection(line[1:])
        if res is not None:
            if sub_res is not None:
                res.add_subsection(sub_res)
            self.file_res.add_section(res)
