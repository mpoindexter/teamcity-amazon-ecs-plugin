# TeamCity Amazon ECS plugin
[![JetBrains incubator project](http://jb.gg/badges/incubator.svg)](https://plugins.jetbrains.com/plugin/9818-kubernetes-cloud-support)
[![plugin status]( 
https://teamcity.jetbrains.com/app/rest/builds/buildType:(id:TestDrive_TeamCityAmazonEcsPlugin_Build)/statusIcon.svg)](https://teamcity.jetbrains.com/viewType.html?buildTypeId=TestDrive_TeamCityAmazonEcsPlugin_Build&guest=1)

TeamCity plugin which allows to run build agents on top of AWS ECS cluster.

## Status

Plugin Development is in progress. Please do not use it in production environment.

## Compatibility

The plugin is compatible with TeamCity 2017.1.x and later.

## Installation

You can [download the plugin](https://teamcity.jetbrains.com/repository/download/TestDrive_TeamCityAmazonEcsPlugin_Build/lastSuccessful/aws-ecs.zip) and install it as an [additional TeamCity plugin](https://confluence.jetbrains.com/display/TCDL/Installing+Additional+Plugins).

## Configuration

The plugin supports Amazon ECS cluster images to start new tasks with a TeamCity build agent running in one of the containers. The plugin supports the [official TeamCity Build Agent Docker image](https://hub.docker.com/r/jetbrains/teamcity-agent) out of the box. You can use your own image as well.

## License

Apache 2.0

## Feedback

Please feel free to post feedback in the repository [issues](https://github.com/ekoshkin/teamcity-amazon-ecs-plugin/issues).

