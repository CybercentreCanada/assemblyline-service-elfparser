import re
import subprocess

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection


class ELFPARSER(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config)

    def start(self):
        self.log.info("Starting ELFPARSER")
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
        for line in output[currentline:]:
            if line == "":
                continue
            if res is None:
                res = ResultSection("Capabilities")
            if line.startswith("\t\t"):
                sub_res.add_line(line[2:])
            elif line.startswith("\t"):
                if sub_res is not None:
                    res.add_subsection(sub_res)
                sub_res = ResultSection(line[1:])
        if res is not None:
            if sub_res is not None:
                res.add_subsection(sub_res)
            self.file_res.add_section(res)
