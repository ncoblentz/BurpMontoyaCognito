plugins {
    id("java")
    `maven-publish`
}

group = "com.nickcoblentz.montoya.aws"
version = "1.0-SNAPSHOT"


//Run -> Edit Configuration -> Gradle-Build, Environment Variables: USERNAME and TOKEN
repositories {
    mavenCentral()
    maven {
        url = uri("https://maven.pkg.github.com/ncoblentz/BurpMontoyaUtilities")
        credentials {
            username = project.findProperty("gpr.user") as String? ?: System.getenv("USERNAME")
            //username = "ncoblentz"
            password = project.findProperty("gpr.key") as String? ?: System.getenv("TOKEN")
            //password = "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"
        }
    }
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.9.1"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    implementation("net.portswigger.burp.extensions:montoya-api:+")
    implementation("com.nickcoblentz.montoya.libraries:burpmontoyautilities:+")
}

tasks.test {
    useJUnitPlatform()
}

publishing {
    repositories {
        maven {
            name = "GitHubPackages"
            url = uri("https://maven.pkg.github.com/ncoblentz/BurpMontoyaCognito")
            credentials {
                username = project.findProperty("gpr.user") as String? ?: System.getenv("USERNAME")
                password = project.findProperty("gpr.key") as String? ?: System.getenv("TOKEN")
            }
        }
    }
    publications {
        register<MavenPublication>("gpr") {
            from(components["java"])
        }
    }
}