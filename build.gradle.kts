import org.gradle.api.tasks.testing.logging.TestExceptionFormat

/*
 * Global Variables
 */
// project version
// pom artifact version used when the built artifact is published
version = "4.0.4"

val junitVersion = "5.10.2"
val fuelVersion = "2.3.1"
val jacksonVersion = "2.17.1"
val gsonVersion = "2.10.1"
val bouncyCastleVersion = "1.70"
val hopliteVersion = "2.7.5"

plugins {
    // Apply the Kotlin JVM plugin to add support for Kotlin on the JVM.
    id("org.jetbrains.kotlin.jvm") version "1.9.24"
    id("maven-publish")
}

kotlin {
    jvmToolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

/*
 * In case that we publish the artifact
 */
publishing {
    publications {
        register("secure-api-gateway-functional-test-framework", MavenPublication::class) {
            pom {
                name.set("secure-api-gateway-functional-test-framework")
                groupId = "com.forgerock.sapi.gateway"
                artifactId = "secure-api-gateway-functional-test-framework"
                version = project.version.toString()
            }
        }
    }
}

repositories {
    mavenLocal()
    mavenCentral()
    maven("https://www.jitpack.io")
    maven("https://maven.forgerock.org/artifactory/community")
}

dependencies {
    implementation(platform("org.jetbrains.kotlin:kotlin-bom"))

    implementation("org.bouncycastle:bcprov-jdk15on:${bouncyCastleVersion}")
    implementation("org.bouncycastle:bcpkix-jdk15on:${bouncyCastleVersion}")

    implementation("com.github.kittinunf.fuel:fuel:${fuelVersion}")
    implementation("com.github.kittinunf.fuel:fuel-jackson:${fuelVersion}")
    implementation("com.github.kittinunf.fuel:fuel-gson:${fuelVersion}")
    implementation("com.google.code.gson:gson:${gsonVersion}")
    implementation("com.fasterxml.jackson.datatype:jackson-datatype-joda:${jacksonVersion}")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:${jacksonVersion}")

    implementation("io.r2:simple-pem-keystore:0.3")
    implementation("org.apache.httpcomponents:httpclient:4.5.14")

    implementation("com.nimbusds:nimbus-jose-jwt:9.0.1")
    implementation("commons-io:commons-io:2.16.1")

    implementation("com.sksamuel.hoplite:hoplite-core:${hopliteVersion}")
    implementation("com.sksamuel.hoplite:hoplite-json:${hopliteVersion}")

    implementation("org.assertj:assertj-core:3.13.2")
    implementation("com.willowtreeapps.assertk:assertk-jvm:0.28.1")

    implementation("org.junit.jupiter:junit-jupiter-api:${junitVersion}")
    implementation("org.junit.jupiter:junit-jupiter-params:${junitVersion}")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:${junitVersion}")
    testImplementation("org.mockito:mockito-core:5.12.0")
}


configure<SourceSetContainer> {
    named("main") {
        java.srcDir("src/main/kotlin")
    }
}

/**
 ********************************************************************
 * TASKS
 ********************************************************************
 */


/*
 * scope generic tasks
 */
tasks {
    test {
        useJUnitPlatform()
        description = "Runs ALL tests"
    }
}

// To generate the tests library
tasks.register<Jar>("generateTestJar") {
    group = "specific"
    description = "Generate a non-executable jar library tests"
    archiveClassifier.set("tests")
    archiveFileName.set("${project.name}-${project.version}-$version.jar")
    from(sourceSets.test.get().allSource)
    from(sourceSets.main.get().allSource)
    dependsOn("testClasses")
    manifest {
        attributes(
            mapOf(
                "Specification-Title" to "Secure API Gateway Functional Tests",
                "Implementation-Title" to project.name,
                "Implementation-Version" to project.version,
                "Created-by" to "${project.version} (forgerock)",
                "Built-by" to System.getProperty("user.name"),
                "Build-Jdk" to JavaVersion.current(),
                "Source-Compatibility" to project.properties["sourceCompatibility"],
                "Target-Compatibility" to project.properties["targetCompatibility"]
            )
        )
    }
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
    println("RUNNING task [$name]")

    // execution conditions (see readme file)
    systemProperty("junit.platform.output.capture.stdout", "true")
    systemProperty("junit.jupiter.extensions.autodetection.enabled", "true")
    /* execution properties */
    // Indicates if this task will fail on the first failed test
    failFast = false
    minHeapSize = "512M"
    maxHeapSize = "2G"
    // You can run your tests in parallel by setting this property to a value greater than 1
    // default value when isn't set in the task
    maxParallelForks = 1
    testLogging.showStandardStreams = true
    testLogging.exceptionFormat = TestExceptionFormat.FULL

    // Disable test output caching as these are integration tests and therefore are environment dependent
    outputs.upToDateWhen { false }
}
