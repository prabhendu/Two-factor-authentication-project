#!/bin/sh

./gradlew build

if [[ $? -ne 0 ]];then
  exit
fi

java -jar build/libs/gs-rest-service-0.1.0.jar
