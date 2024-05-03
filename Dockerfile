
# Use a base image
FROM ubuntu:latest

# Set the working directory
WORKDIR /app/ebpf_project

# Install necessary dependencies
RUN apt-get update && \
    apt-get -y install sudo && \
    apt-get install -y build-essential && \
    apt-get install -y make && \
    #ulimit -l unlimited
# Run the bootstrap script
CMD ["make", "run"]