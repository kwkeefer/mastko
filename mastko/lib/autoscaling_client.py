import os

import boto3  # type: ignore

from mastko.lib.exceptions import AutoScalingException
from mastko.lib.logger import get_logger

log = get_logger("mastko.lib.autoscaling_client")


class AutoscalingClient:
    def __init__(self) -> None:
        self.autoscaling_group = os.environ["MASTKO_ASG_NAME"]
        self.client = boto3.client("autoscaling", region_name=os.environ["AWS_REGION_NAME"])

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
            raise AutoScalingException(f"Failed to get autoscaling groups: {ex}")

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
            raise AutoScalingException(f"Failed to detatch instance from autoscaling group: {ex}")
