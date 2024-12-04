FROM python:3.9

ARG SOURCE
ARG COMMIT_HASH
ARG COMMIT_ID
ARG BUILD_TIME
LABEL source=${SOURCE}
LABEL commit_hash=${COMMIT_HASH}
LABEL commit_id=${COMMIT_ID}
LABEL build_time=${BUILD_TIME}

ARG container_user=mosip
ARG container_user_group=mosip
ARG container_user_uid=1001
ARG container_user_gid=1001

# Create user group
RUN groupadd -r ${container_user_group} && useradd -u ${container_user_uid} -r -g ${container_user_group} -s /bin/bash -m -d /home/${container_user} ${container_user}
RUN chown -R ${container_user}:${container_user} /home/${container_user}
WORKDIR /home/${container_user}
USER ${container_user}

ENV MYDIR=`pwd`
ENV DATE="$(date --utc +%FT%T.%3NZ)"
ENV ENABLE_INSECURE=false
ENV MODULE=


ENV db-server=
ENV db-port=
ENV db-su-user=
ENV postgres-password=

COPY partner.properties .
COPY requirements.txt .
COPY checkupdate.py .
COPY bootstrap.properties .
RUN pip install --no-cache-dir -r requirements.txt
CMD ["python", "checkupdate.py"]