const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const app = express();
require("dotenv").config();
const port = process.env.PORT || 3000;

//firebase admin
const admin = require("firebase-admin");
const serviceAccount = require("./etuitionbd-sakinkhan-firebase-adminsdk.json");
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// middlewares
app.use(express.json());
app.use(cors());

const verifyFBToken = async (req, res, next) => {
  //   console.log("headers in the MIddLeWare", req.headers.authorization);

  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).send({ message: "unauthorized access" });
  }

  try {
    const idToken = token?.split(" ")?.[1];
    if (!idToken) return res.status(401).send({ message: "Invalid token" });
    const decoded = await admin.auth().verifyIdToken(idToken);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).send({ message: "unauthorized access" });
  }
};

const verifyAdmin = (usersCollection) => async (req, res, next) => {
  try {
    const fbEmail = req.user?.email;
    if (!fbEmail) return res.status(401).send({ message: "unauthorized" });

    const user = await usersCollection.findOne({ email: fbEmail });
    if (!user || !user.isAdmin) {
      return res.status(403).send({ message: "forbidden access: admin only" });
    }
    next();
  } catch (err) {
    console.error("verifyAdmin error", err);
    res.status(500).send({ message: "server error" });
  }
};

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@sakinkhan.slpidbs.mongodb.net/?appName=SakinKhan`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();

    // Collections
    const db = client.db("eTuitionBD_db");
    const usersCollection = db.collection("users");
    const tuitionPostsCollection = db.collection("tuitionPosts");
    const tuitionApplicationsCollection = db.collection(
      "tuitionApplicationsCollection"
    );

    /*-----------USER ENDPOINTS---------*/
    // GET all users
    app.get("/users", verifyFBToken, async (req, res) => {
      const searchText = req.query.searchText;
      const query = {};

      if (searchText) {
        query.$or = [
          { displayName: { $regex: searchText, $options: "i" } },
          { email: { $regex: searchText, $options: "i" } },
        ];
      }

      const cursor = usersCollection
        .find(query)
        .sort({ createdAt: -1 })
        .limit(7);
      const result = await cursor.toArray();
      res.send(result);
    });

    // GET single user by email
    app.get("/users/:email", verifyFBToken, async (req, res) => {
      try {
        const email = req.params.email;
        const user = await usersCollection.findOne({ email });

        if (!user) {
          return res.status(404).send({ error: "User not found" });
        }

        res.send(user);
      } catch (error) {
        console.error("GET /users/:email error:", error);
        res.status(500).send({ error: "Internal Server Error" });
      }
    });

    // GET users filter by role
    app.get("/users/:email/role", verifyFBToken, async (req, res) => {
      const email = req.params.email;
      const query = { email };
      const user = await usersCollection.findOne(query);
      if (!user) return res.status(404).send({ error: "User not found" });
      res.send({ role: user.role || "student", isAdmin: !!user.isAdmin });
    });

    // create/POST a new user
    app.post("/users", async (req, res) => {
      const user = req.body;

      // Ensure role exists
      if (!user.role) {
        return res.status(400).send({ error: "Role is required" });
      }

      // Prevent duplicate email entry
      const exists = await usersCollection.findOne({ email: user.email });
      if (exists) {
        return res.status(409).send({ error: "User already exists" });
      }

      const result = await usersCollection.insertOne(user);
      res.send(result);
    });

    // PATCH / Update user info:
    app.patch(
      "/users/:id",
      verifyFBToken,
      verifyAdmin(usersCollection),
      async (req, res) => {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };

        const { name, phone, role, photoURL, verified } = req.body;

        const updateFields = {};
        if (name) updateFields.name = name;
        if (phone) updateFields.phone = phone;
        if (photoURL) updateFields.photoURL = photoURL;
        if (role) updateFields.role = role;
        if (typeof verified === "boolean") updateFields.verified = verified;

        const result = await usersCollection.updateOne(query, {
          $set: updateFields,
        });

        res.send(result);
      }
    );

    // PATCH/ Update user role
    app.patch(
      "/users/:id/admin",
      verifyFBToken,
      verifyAdmin(usersCollection),
      async (req, res) => {
        try {
          const id = req.params.id;
          const query = { _id: new ObjectId(id) };
          const updatedDoc = {
            $set: {
              isAdmin: !!req.body.isAdmin,
            },
          };
          const result = await usersCollection.updateOne(query, updatedDoc);
          res.send(result);
        } catch (err) {
          console.error("PATCH /users/:id/admin error:", err);
          res.status(500).send({ error: "Internal Server Error" });
        }
      }
    );

    // DELETE User
    app.delete(
      "/users/:id",
      verifyFBToken,
      verifyAdmin(usersCollection),
      async (req, res) => {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await usersCollection.deleteOne(query);
        res.send(result);
      }
    );

    /*-----------Tuition Post ENDPOINTS---------*/
    // GET all tuition posts (latest first)
    app.get("/tuition-posts", async (req, res) => {
      try {
        const query = {};
        const search = req.query.search;

        if (search) {
          query.$or = [
            { subject: { $regex: search, $options: "i" } },
            { classLevel: { $regex: search, $options: "i" } },
            { location: { $regex: search, $options: "i" } },
            { studentName: { $regex: search, $options: "i" } },
            { description: { $regex: search, $options: "i" } },
          ];
        }
        const cursor = tuitionPostsCollection
          .find(query)
          .sort({ createdAt: -1 });
        const result = await cursor.toArray();
        res.send(result);
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: "Failed to fetch tuition posts" });
      }
    });
    // GET all my tuition posts
    app.get("/tuition-posts/my-posts", verifyFBToken, async (req, res) => {
      const fbEmail = req.user?.email;
      if (!fbEmail) {
        return res.status(400).send({ error: "Invalid authentication" });
      }

      const cursor = tuitionPostsCollection
        .find({ userEmail: fbEmail })
        .sort({ createdAt: -1 });
      const result = await cursor.toArray();
      res.send(result);
    });

    // GET Single tuition post by id
    app.get("/tuition-posts/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await tuitionPostsCollection.findOne(query);
      res.send(result);
    });

    // POST/ Create a tuition post
    app.post("/tuition-posts", verifyFBToken, async (req, res) => {
      const {
        subject,
        classLevel,
        location,
        budget,
        schedule,
        description,
        contactEmail,
      } = req.body;

      //get student name
      const fbEmail = req.user.email;
      const dbUser = await usersCollection.findOne({ email: fbEmail });
      const studentName = dbUser?.name || "Unknown";

      console.log("contactEmail + studentName", contactEmail, studentName);

      // Basic validation
      if (
        !subject ||
        !classLevel ||
        !location ||
        !budget ||
        !contactEmail ||
        !description
      ) {
        return res.status(400).send({
          error: "Missing required fields.",
          required: [
            "subject",
            "classLevel",
            "location",
            "budget",
            "contactEmail",
            "description",
          ],
        });
      }
      const newPost = {
        studentName,
        subject,
        classLevel,
        location,
        budget: Number(budget),
        schedule: schedule || "",
        description,
        contactEmail,
        status: "Approved", // TODO make pending once admin done
        createdAt: new Date(),
        userEmail: fbEmail,
      };
      console.log("NEW POST", newPost);

      const result = await tuitionPostsCollection.insertOne(newPost);
      res.send(result);
    });

    // PATCH/edit tuition posts
    app.patch("/tuition-posts/:id", verifyFBToken, async (req, res) => {
      const id = req.params.id;
      const fbEmail = req.user?.email;
      if (!fbEmail)
        return res.status(400).send({ error: "Invalid authentication" });

      const query = { _id: new ObjectId(id) };
      const existingPost = await tuitionPostsCollection.findOne(query);
      if (!existingPost)
        return res.status(404).send({ error: "Tuition post not found" });

      if (existingPost.userEmail !== fbEmail)
        return res.status(403).send({ error: "Forbidden. Not your post." });

      const {
        subject,
        classLevel,
        location,
        budget,
        schedule,
        description,
        contactEmail,
      } = req.body;

      const updatedFields = {};
      if (subject) updatedFields.subject = subject;
      if (classLevel) updatedFields.classLevel = classLevel;
      if (location) updatedFields.location = location;
      if (budget !== undefined && budget !== "")
        updatedFields.budget = Number(budget);
      if (schedule !== undefined) updatedFields.schedule = schedule;
      if (description) updatedFields.description = description;
      if (contactEmail) updatedFields.contactEmail = contactEmail;
      updatedFields.updatedAt = new Date();

      const result = await tuitionPostsCollection.updateOne(query, {
        $set: updatedFields,
      });

      if (result.matchedCount === 0) {
        return res.status(404).send({ error: "Tuition post not found" });
      }

      res.send({ message: "Tuition post updated successfully", updatedFields });
    });

    // DELETE tuition posts
    app.delete("/tuition-posts/:id", verifyFBToken, async (req, res) => {
      const id = req.params.id;

      const fbEmail = req.user?.email;
      if (!fbEmail) {
        return res.status(400).send({ error: "Invalid authentication" });
      }

      // Find the post
      const existingPost = await tuitionPostsCollection.findOne({
        _id: new ObjectId(id),
      });

      if (!existingPost) {
        return res.status(404).send({ error: "Tuition post not found" });
      }

      // Ownership check
      if (existingPost.userEmail !== fbEmail) {
        return res
          .status(403)
          .send({ error: "Forbidden. You cannot delete this post." });
      }

      const result = await tuitionPostsCollection.deleteOne({
        _id: new ObjectId(id),
      });

      res.send(result);
    });

    /*-----------Tutor Application ENDPOINTS---------*/
    // GET all applications for a specific tuition post for Student dashboard
    app.get(
      "/applications/by-tuition/:tuitionPostId",
      verifyFBToken,
      async (req, res) => {
        const tuitionPostId = req.params.tuitionId;

        const result = await tuitionApplicationsCollection
          .find({ tuitionPostId })
          .sort({ createdAt: -1 })
          .toArray();
        res.send(result);
      }
    );

    // GET all applications created by the logged-in tutor
    app.get(
      "/applications/my-applications",
      verifyFBToken,
      async (req, res) => {
        const fbEmail = req.user?.email;

        if (!fbEmail) {
          return res.status(400).send({ error: "Invalid authentication" });
        }

        const result = await tuitionApplicationsCollection
          .find({ tutorEmail: fbEmail })
          .sort({ createdAt: -1 })
          .toArray();
        res.send(result);
      }
    );

    // POST - Tutor applies to a tuition
    app.post("/applications", verifyFBToken, async (req, res) => {
      const { tuitionPostId, qualifications, experience, expectedSalary } =
        req.body;
      const fbEmail = req.user.email;
      const dbUser = await usersCollection.findOne({ email: fbEmail });

      if (!dbUser || dbUser.role !== "tutor") {
        return res.status(403).send({ error: "Only tutors can apply." });
      }

      if (!tuitionPostId || !qualifications || !experience || !expectedSalary) {
        return res.status(400).send({ error: "Missing required fields" });
      }

      // Prevent duplicate application by the same tutor
      const existing = await tuitionApplicationsCollection.findOne({
        tuitionPostId,
        tutorEmail: fbEmail,
      });

      if (existing) {
        return res
          .status(409)
          .send({ error: "Already applied to this tuition." });
      }

      const newApplication = {
        tuitionPostId,
        tutorName: dbUser.name,
        tutorEmail: dbUser.email,
        qualifications,
        experience,
        expectedSalary: Number(expectedSalary),
        status: "Pending",
        createdAt: new Date(),
      };

      const result = await tuitionApplicationsCollection.insertOne(
        newApplication
      );
      res.send(result);
    });

    // PATCH - Approve or Reject tutor application (Student performs this)
    app.patch("/applications/:id", verifyFBToken, async (req, res) => {
      const applicationId = req.params.id;
      const { status } = req.body;
      const query = { _id: new ObjectId(applicationId) };

      const application = await tuitionApplicationsCollection.findOne(query);
      if (!application) {
        return res.status(404).send({ error: "Application not found" });
      }

      // Find the associated tuition post
      const tuitionPostQuery = { _id: new ObjectId(application.tuitionPostId) };
      const tuitionPost = await tuitionPostsCollection.findOne(
        tuitionPostQuery
      );

      // Only the student who posted the tuition can approve/reject
      const fbEmail = req.user.email;
      if (tuitionPost.userEmail !== fbEmail) {
        return res.status(403).send({ error: "Unauthorized action" });
      }

      const updatedDoc = {
        $set: {
          status,
          updatedAt: new Date(),
        },
      };
      const result = await tuitionApplicationsCollection.updateOne(
        query,
        updatedDoc
      );
      res.send(result);
    });

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("eTuitionBD server is Sprinting!");
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
