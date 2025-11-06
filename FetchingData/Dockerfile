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

# Expose port
EXPOSE 8082

# Start the app with port configuration
ENTRYPOINT ["java", "-jar", "app.jar", "--server.port=8082", "--server.address=0.0.0.0"]
