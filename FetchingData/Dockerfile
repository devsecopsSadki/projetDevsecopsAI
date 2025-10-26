FROM openjdk:21-slim

# Install debugging tools
RUN apt-get update && apt-get install -y \
    netcat-openbsd \
    telnet \
    dnsutils \
    iputils-ping \
    curl \
    vim \
    less \
    && rm -rf /var/lib/apt/lists/*


# Copy your app
VOLUME /tmp
COPY target/*.jar app.jar

# Start the app
ENTRYPOINT ["java", "-jar", "app.jar"]
