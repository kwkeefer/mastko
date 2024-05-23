import os
from datetime import datetime
from typing import Dict, List, Mapping, Sequence

from mastko.config.configs import Configs
from mastko.data.eip import EIP
from mastko.data.target import Target
from mastko.lib.autoscaling_client import AutoscalingClient
from mastko.lib.ec2_client import Ec2Client
from mastko.lib.exceptions import BruteforcerException
from mastko.lib.logger import get_logger

log = get_logger("mastko.lib.bruteforcer")


class Bruteforcer:
    """
    The Bruteforcer is capable of rotating the public IP on AWS EC2 and comparing against target list to
    check for takeovers.
    """

    def __init__(self, targets: Sequence[Target]):
        self.targets = targets
        self.target_hash = self._get_targets_grouped_by_ip(self.targets)
        self.region = os.environ["AWS_REGION_NAME"]
        self.ec2_client = Ec2Client(aws_region=self.region)
        self.asg_client = AutoscalingClient(aws_region=self.region)
        self.eip = EIP(
            allocation_id=os.environ["MASTKO_EIP_ALLOCATION_ID"], ip_address=os.environ["MASTKO_EIP"]
        )

    def _get_targets_grouped_by_ip(self, targets: Sequence[Target]) -> Mapping[str, Sequence[Target]]:
        target_hash: Dict[str, List[Target]] = {}
        for target in targets:
            if target.ip_address not in target_hash:
                target_hash[target.ip_address] = []

            target_hash[target.ip_address].append(target)

        return target_hash

    def _cycle_eip_through_autoscaling_group(self, autoscaling_group_name: str) -> None:
        try:
            instance_ids = self.asg_client.get_instances_in_autoscaling_group(autoscaling_group_name)
            self.asg_client.cycle_eip_through_ec2_instance(instance_ids, self.eip.allocation_id)
        except Exception as err:
            message = f"Failed to cycle eip through autoscaling group: {autoscaling_group_name}. ERROR: {err}"
            log.error(message)
            raise BruteforcerException(message)

    def _check_if_takeover(self, ip_to_ec2_dict: list) -> list:
        for ip, instance_id in ip_to_ec2_dict.items():
            if ip in self.target_hash:
                log.info(
                    f"SUCESSFULL ATTEMPT, takeover match found. ec2_used: {instance_id}, public_ip: {ip}"
                )
                self._process_successful_takeover(instance_id, ip)

    def _process_successful_takeover(self, instance_id: str, takeover_ip: str) -> None:
        self.ec2_client.rename_ec2_instance(instance_id, Configs.successful_takeover_ec2_name)
        successful_takeover_targets = self.target_hash[takeover_ip]
        associated_dns_names = [target.domain for target in successful_takeover_targets]
        tags = []
        for index in range(len(associated_dns_names)):
            log.info(
                f"SUCCESSFUL TAKEOVER. takeover_ip: {takeover_ip}, "
                f"target: {associated_dns_names[index]}, ec2 used: {instance_id}"
            )
            tags.append({"Key": f"domain_{index}", "Value": associated_dns_names[index]})
        self.ec2_client.tag_instance(instance_id=instance_id, tags=tags)
        self.asg_client.detatch_instance_from_autoscaling_group(instance_id)

    def run(self, iterations: int) -> None:
        try:
            # TODO: fix iteration logic.. it's not the same now that we're using ASGs
            iteration_counter: int = 0
            start_time: datetime = datetime.now().replace(microsecond=0)
            while iteration_counter < iterations:
                instance_ids = self.asg_client.get_instances_in_autoscaling_group()
                ip_to_ec2_dict = self.ec2_client.get_ip_to_instance_id_dict(instance_ids)
                self._check_if_takeover(ip_to_ec2_dict)
                self._cycle_eip_through_autoscaling_group()
                iteration_counter += 1

            end_time: datetime = datetime.now().replace(microsecond=0)
            log.info(
                f"MasTKO finished executing {iterations} iterations in {end_time - start_time} (HH:MM:SS) time."
            )
        except Exception as ex:
            message = f"Exception caught in bruteforce handler, error: {ex}"
            log.error(message)
            log.exception(ex)
            raise BruteforcerException(message)
