import re
import subprocess

from assemblyline_v4_service.common import helper
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Heuristic, Result, ResultSection


class ELFPARSER(ServiceBase):
    def __init__(self, config=None):
        super(ELFPARSER, self).__init__(config)

    def start(self):
        self.log.info("Starting ELFPARSER")
        self.header_line = re.compile(".* - Score: (\\d+) \\[Family: (.*)\\]")
        # Create mapping of name -> heur-id
        """
        fileFunctions, 15 # fopen/close, etc
        networkFunctions, 5
        processManipulation, 15 # execve, close, raise, etc
        pipeFunctions, 15 #pclose, popen
        crypto, 1 # rand() and the like
        infoGathering, 50 # /proc/{cpuinfo,meminfo,stat}
        envVariables, 75 # no 100 b/c getenv() is legit
        permissions, 35 #chown, chmod
        syslog, 5
        packetSniff, 20 # pcap_{open,close,read,loop}
        shell, 100 # system(). If not malicious at least identifying weak code.
        packed, 100
        irc, 50
        http, 100
        compression, 20
        ipAddress, 20
        url, 5
        hooking, 100 #dlsym()
        antidebug, 105 #elf obfuscation
        filePath, 5
        dropper, 500 # Finds elf headers at offsets other than 0x0. Binwalk-esq
        """
        heuristics = helper.get_heuristics()
        self.heuristics = {}
        for heuristic in heuristics.values():
            self.heuristics[heuristic.name] = heuristic

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
        sub_res_title = None
        sub_res_lines = []
        for line in output[currentline:]:
            if line == "":
                continue
            if res is None:
                res = ResultSection("Capabilities")
            if line.startswith("\t\t"):
                sub_res_lines.append(line[2:])
            elif line.startswith("\t"):
                if sub_res_title is not None:
                    if sub_res_title in self.heuristics:
                        sub_res = ResultSection(
                            sub_res_title,
                            heuristic=Heuristic(
                                int(self.heuristics[sub_res_title].heur_id), frequency=len(sub_res_lines)
                            ),
                        )
                    else:
                        sub_res = ResultSection(sub_res_title)
                    sub_res.add_lines(sub_res_lines)
                    res.add_subsection(sub_res)
                    sub_res_lines = []
                sub_res_title = line[1:]
        if res is not None:
            if sub_res_title is not None:
                if sub_res_title in self.heuristics:
                    sub_res = ResultSection(
                        sub_res_title,
                        heuristic=Heuristic(int(self.heuristics[sub_res_title].heur_id), frequency=len(sub_res_lines)),
                    )
                else:
                    sub_res = ResultSection(sub_res_title)
                sub_res.add_lines(sub_res_lines)
                res.add_subsection(sub_res)
            self.file_res.add_section(res)
