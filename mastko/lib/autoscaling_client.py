import os

import boto3

from mastko.lib.exceptions import AutoscalingException
from mastko.lib.logger import get_logger

log = get_logger("mastko.lib.autoscaling_client")


class AutoscalingClient:
    def __init__(self, region: str) -> None:
        self.client = boto3.client("autoscaling", region_name=region)
        self.autoscaling_group = os.environ["MASTKO_ASG_NAME"]

    def get_instances_in_autoscaling_group(self) -> list[str]:
        """
        Gets instance ids in an autoscaling group.  Only instances in the "InService" state are returned.
        """
        try:
            resp = self.client.describe_auto_scaling_groups(AutoScalingGroupNames=[self.autoscaling_group])
            instance_ids = []
            for group in resp["AutoScalingGroups"]:
                for instance in group["Instances"]:
                    if instance["LifecycleState"] == "InService":
                        instance_ids.append(instance["InstanceId"])
            return instance_ids
        except Exception as ex:
            log.error(ex)
            raise AutoscalingException(f"Failed to get autoscaling groups: {ex}")

    def detatch_instance_from_autoscaling_group(self, instance_id: str) -> None:
        """
        Detatches an instance from an autoscaling group
        """
        try:
            self.client.detach_instances(
                InstanceIds=[instance_id],
                AutoScalingGroupName=self.autoscaling_group,
                ShouldDecrementDesiredCapacity=False,
            )
        except Exception as ex:
            log.error(ex)
            raise AutoscalingException(f"Failed to detatch instance from autoscaling group: {ex}")
