plugins {
    id("java")
    id("maven-publish")

}

group = "com.nickcoblentz.montoya.aws"
version = "0.1.7"


//Run -> Edit Configuration -> Gradle-Build, Environment Variables: USERNAME and TOKEN
repositories {
    mavenCentral()
    /*maven {
        url = uri("https://maven.pkg.github.com/ncoblentz/BurpMontoyaUtilities")
        credentials {
            username = project.findProperty("gpr.user") as String? ?: System.getenv("GHUSERNAME")
            password = project.findProperty("gpr.key") as String? ?: System.getenv("GHTOKEN")
        }
    }*/
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.9.1"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    implementation("net.portswigger.burp.extensions:montoya-api:2023.10.3")
    //implementation("com.nickcoblentz.montoya.libraries:burpmontoyautilities:+")
    implementation("org.json:json:+")

}

tasks.test {
    useJUnitPlatform()
}
/*
val fatJar = task("fatJar", type = Jar::class) {
    val baseName = "${project.name}-all" //rootProject.name
    // manifest Main-Class attribute is optional.
    // (Used only to provide default main class for executable jar)
    manifest {
        //attributes["Main-Class"] = "example.HelloWorldKt" // fully qualified class name of default main class
        attributes["Implementation-Title"]=rootProject.name
    }
    from(configurations.runtime.map({ if (it.isDirectory) it else zipTree(it) }))
    with(tasks["jar"] as CopySpec)
}
*/
tasks {
    val fatJar = register<Jar>("fatJar") {
        //dependsOn.addAll(listOf("compileJava", "compileKotlin", "processResources")) // We need this for Gradle optimization to work
        dependsOn.add("build")
        archiveClassifier.set("fatjar") // Naming the jar
        duplicatesStrategy = DuplicatesStrategy.EXCLUDE
        //manifest { attributes(mapOf("Main-Class" to application.mainClass)) } // Provided we set it up in the application plugin configuration
        val sourcesMain = sourceSets.main.get()
        val contents = configurations.runtimeClasspath.get()
                .map { if (it.isDirectory) it else zipTree(it) } +
                sourcesMain.output
        from(contents)
    }
    /*build {
        dependsOn(fatJar) // Trigger fat jar creation during build
    }*/
}

publishing {
    repositories {
        maven {
            name = "GitHubPackages"
            url = uri("https://maven.pkg.github.com/ncoblentz/BurpMontoyaCognito")
            credentials {
                username = project.findProperty("gpr.user") as String? ?: System.getenv("GHUSERNAME")
                password = project.findProperty("gpr.key") as String? ?: System.getenv("GHTOKEN")
            }
        }
    }
    publications {
        register<MavenPublication>("gpr") {
            //from(components["java"])
            artifact(tasks.findByPath("fatJar"))
        }

    }
}