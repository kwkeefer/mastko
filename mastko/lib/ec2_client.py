from typing import Dict, List, Optional

import boto3  # type: ignore

from mastko.data.eip import EIP
from mastko.lib.exceptions import Ec2ClientException
from mastko.lib.logger import get_logger

log = get_logger("mastko.lib.ec2_client")


class Ec2Client:
    """
    Helper class for EC2 functions
    """

    def __init__(self, aws_region: str):
        self.aws_region = aws_region
        self.ec2_client = boto3.client("ec2", region_name=self.aws_region)

    def get_eip(self, ip: str) -> EIP:
        try:
            results = self.ec2_client.describe_addresses(
                Filters=[{"Name": "public-ip", "Values": [ip]}, {"Name": "domain", "Values": ["vpc"]}]
            )
            if len(results["Addresses"]) > 1:
                raise Ec2ClientException(
                    f"Ambiguous result returned by AWS, got more than one results for public-ip: {ip}, "
                    f"AWS response: {results}"
                )

            if len(results["Addresses"]) == 0:
                raise Ec2ClientException(
                    f"No EIP found for public-ip: {ip}. It might not be allocated or cannot be used with "
                    "a AWS VPC. Please refer: "
                    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/"
                    "elastic-ip-addresses-eip.html#using-instance-addressing-eips-allocating"
                )

            return EIP(allocation_id=results["Addresses"][0]["AllocationId"], ip_address=ip)
        except Exception as ex:
            msg = f"Failed to get eip with public-ip: {ip}. ERROR: {ex}"
            log.error(msg)
            log.exception(ex)
            raise Ec2ClientException(msg)

    def tag_instance(self, instance_id: str, tags: List[Dict[str, str]]) -> Optional[dict]:
        try:
            response = self.ec2_client.create_tags(
                Resources=[
                    instance_id,
                ],
                Tags=tags,
            )
            return response
        except Exception as ex:
            msg = f"Failed to tag an instance: {instance_id}. ERROR: {ex}"
            log.error(msg)
            log.exception(ex)
            raise Ec2ClientException(msg)

    def rename_ec2_instance(self, instance_id: str, new_name: str) -> Optional[dict]:
        try:
            response = self.ec2_client.create_tags(
                Resources=[
                    instance_id,
                ],
                Tags=[
                    {
                        "Key": "Name",
                        "Value": new_name,
                    },
                ],
            )
            return response
        except Exception as ex:
            msg = f"Failed to rename instance: {instance_id}, new_name: {new_name}. ERROR: {ex}"
            log.error(msg)
            log.exception(ex)
            raise Ec2ClientException(msg)

    def cycle_eip_through_instances(self, instance_ids: list[str], eip_id: str) -> None:
        try:
            for instance_id in instance_ids:
                self.ec2_client.associate_address(AllocationId=eip_id, InstanceId=instance_id)
        except Exception as err:
            message = (
                f"Failed to cycle eip through instances: {instance_ids}, " f"eip_id: {eip_id}. ERROR: {err}"
            )
            log.error(message)
            raise Ec2ClientException(message)

    def get_ip_to_instance_id_dict(self, instance_ids: list) -> dict[str, str]:
        """
        Gets public ip addresses of instances
        Returns a dictionary of {public_ip: instance_id, ...}
        """
        try:
            response = self.ec2_client.describe_instances(
                Filters=[
                    {
                        "Name": "instance-id",
                        "Values": instance_ids,
                    },
                ],
            )

            if not response["Reservations"]:
                raise Ec2ClientException(f"No instances found for instance_ids: {instance_ids}")

            return {
                instance["PublicIpAddress"]: instance["InstanceId"]
                for reservation in response["Reservations"]
                for instance in reservation["Instances"]
            }

        except Exception as err:
            message = f"Failed to get public ip addresses of intances: {instance_ids}. ERROR: {err}"
            log.error(message)
            log.exception(err)
            raise Ec2ClientException(message)
