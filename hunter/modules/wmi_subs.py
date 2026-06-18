from typing import List
from ..base import HunterModule, Detection
from .. import utils


class WMISubscriptionHunter(HunterModule):
    name = "wmi_subs"
    technique_id = "T1546.003"
    technique_name = "Event Triggered Execution: WMI Event Subscription"
    artifact = "Permanent WMI Event Subscription"
    description = (
        "Objects in the root\\subscription namespace (__EventFilter, "
        "__EventConsumer, __FilterToConsumerBinding). When an event matching "
        "the filter fires, WMI runs the consumer's payload. Rarely used by "
        "legitimate software — common APT persistence (T1546.003)."
    )

    def run(self) -> List[Detection]:
        out: List[Detection] = []
        script = (
            "$f=Get-WmiObject -Namespace root\\subscription -Class __EventFilter;"
            "$c=Get-WmiObject -Namespace root\\subscription -Class __EventConsumer;"
            "$b=Get-WmiObject -Namespace root\\subscription -Class __FilterToConsumerBinding;"
            "foreach($x in $c){"
            "  $cmd=$x.CommandLineTemplate; if(-not $cmd){$cmd=$x.ScriptText}; if(-not $cmd){$cmd=$x.ExecutablePath};"
            "  Write-Output ('CONSUMER|'+$x.__CLASS+'|'+$x.Name+'|'+$cmd)"
            "};"
            "foreach($x in $f){ Write-Output ('FILTER|'+$x.Name+'|'+$x.Query) };"
            "foreach($x in $b){ Write-Output ('BINDING|'+$x.Filter+'|'+$x.Consumer) }"
        )
        text = utils.run_powershell(script, timeout=30)
        # Only emit when a dangerous consumer class is present. NTEventLogEvent /
        # SMTPEvent consumers are shipped with Windows (SCM Event Log, etc.) and
        # produce no execution — they are not persistence vectors. The two
        # consumer classes that DO execute code are CommandLineEventConsumer
        # and ActiveScriptEventConsumer.
        dangerous_consumers = []
        for line in text.splitlines():
            parts = line.split("|", 3)
            if len(parts) < 2 or parts[0] != "CONSUMER":
                continue
            cls, name = parts[1], parts[2] if len(parts) > 2 else ""
            cmd = parts[3] if len(parts) > 3 else ""
            if cls not in ("CommandLineEventConsumer", "ActiveScriptEventConsumer"):
                continue
            dangerous_consumers.append(name)
            out.append(self.make_detection(
                location=f"root\\subscription\\{cls}",
                name=name, value=cmd,
                reasons=[f"WMI {cls} present (executes code on event — nearly never legitimate)"],
                metadata={"rare_technique": True, "consumer_class": cls},
            ))
        # Filters / bindings only matter when tied to a dangerous consumer.
        if dangerous_consumers:
            for line in text.splitlines():
                parts = line.split("|", 3)
                if not parts or not parts[0]:
                    continue
                if parts[0] == "BINDING" and len(parts) >= 3 and \
                   any(c in parts[2] for c in dangerous_consumers):
                    out.append(self.make_detection(
                        location="root\\subscription\\__FilterToConsumerBinding",
                        name="Binding", value=f"{parts[1]} -> {parts[2]}",
                        reasons=["Binding ties filter to dangerous consumer"],
                        metadata={"rare_technique": True},
                    ))
        return out
