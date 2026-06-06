FROM eclipse-temurin:21-jdk AS build
WORKDIR /work
COPY . .
RUN ./mvnw -B package -DskipTests || mvn -B package -DskipTests
FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /work/target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/app.jar"]
