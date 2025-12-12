const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const app = express();
require("dotenv").config();
const port = process.env.PORT || 5000;

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
    const tuitionApplicationsCollection = db.collection("tuitionApplications");
    const countersCollection = db.collection("counters");

    // Ensure unique indexes at server startup
    await tuitionPostsCollection.createIndex(
      { tuitionCode: 1 },
      { unique: true }
    );
    await tuitionApplicationsCollection.createIndex(
      { applicationCode: 1 },
      { unique: true }
    );

    // Code generator
    const getNextCode = async (name, prefix) => {
      let counter;
      let codeExists = true;
      let nextValue;

      while (codeExists) {
        // Increment counter
        counter = await countersCollection.findOneAndUpdate(
          { name },
          { $inc: { value: 1 } },
          { upsert: true, returnDocument: "after" }
        );

        nextValue = counter.value;
        const newCode = `${prefix}-${nextValue}`;

        // Check both collections for duplicates
        const existingPost = await tuitionPostsCollection.findOne({
          tuitionCode: newCode,
        });
        const existingApplication = await tuitionApplicationsCollection.findOne(
          { applicationCode: newCode }
        );

        if (!existingPost && !existingApplication) {
          codeExists = false;
        }
      }

      return `${prefix}-${nextValue}`;
    };

    /* =========================================================
       USER RELATED APIs
    ========================================================== */
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

    /* =========================================================
       TUITION POSTS APIs
    ========================================================== */
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

    // POST /tuition-posts - Create Tuition Post
    app.post("/tuition-posts", verifyFBToken, async (req, res) => {
      try {
        const {
          subject,
          classLevel,
          location,
          budget,
          schedule,
          description,
          contactEmail,
        } = req.body;

        if (
          !subject ||
          !classLevel ||
          !location ||
          !budget ||
          !contactEmail ||
          !description
        ) {
          return res.status(400).send({ error: "Missing required fields" });
        }

        const fbEmail = req.user.email;
        const dbUser = await usersCollection.findOne({ email: fbEmail });

        const newPost = {
          tuitionCode: await getNextCode("tuitionCode", "TP"),
          studentName: dbUser?.name || "Unknown",
          userEmail: fbEmail,
          subject,
          classLevel,
          location,
          budget: Number(budget),
          schedule: schedule || "",
          description,
          contactEmail,
          status: "approved", // later use "Pending" for admin flow
          createdAt: new Date(),
        };

        const result = await tuitionPostsCollection.insertOne(newPost);
        res.send({
          success: true,
          insertedId: result.insertedId,
          tuitionCode: newPost.tuitionCode,
        });
      } catch (err) {
        if (err.code === 11000) {
          // Mongo duplicate key error
          return res
            .status(409)
            .send({ error: "Duplicate tuition code, please try again" });
        }
        console.error(err);
        res.status(500).send({ error: "Internal server error" });
      }
    });

    // PATCH/edit tuition posts
    app.patch("/tuition-posts/:id", verifyFBToken, async (req, res) => {
      const id = req.params.id;
      const fbEmail = req.user?.email;

      if (!fbEmail)
        return res.status(400).send({ error: "Invalid authentication" });

      let postId;
      try {
        postId = new ObjectId(id);
      } catch {
        return res.status(400).send({ error: "Invalid tuition post ID" });
      }

      const existingPost = await tuitionPostsCollection.findOne({
        _id: postId,
      });
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
      if (subject) updatedFields.subject = subject.trim();
      if (classLevel) updatedFields.classLevel = classLevel.trim();
      if (location) updatedFields.location = location.trim();
      if (budget !== undefined && budget !== "")
        updatedFields.budget = Number(budget);
      if (schedule !== undefined) updatedFields.schedule = schedule.trim();
      if (description) updatedFields.description = description.trim();
      if (contactEmail) updatedFields.contactEmail = contactEmail.trim();
      updatedFields.updatedAt = new Date();

      const result = await tuitionPostsCollection.findOneAndUpdate(
        { _id: postId },
        { $set: updatedFields },
        { returnDocument: "after" } // Return the updated document
      );

      res.send({
        message: "Tuition post updated successfully",
        updatedPost: result.value,
      });
    });

    // DELETE tuition posts
    app.delete("/tuition-posts/:id", verifyFBToken, async (req, res) => {
      const id = req.params.id;
      const fbEmail = req.user?.email;

      if (!fbEmail)
        return res.status(400).send({ error: "Invalid authentication" });

      let postId;
      try {
        postId = new ObjectId(id);
      } catch {
        return res.status(400).send({ error: "Invalid tuition post ID" });
      }

      const existingPost = await tuitionPostsCollection.findOne({
        _id: postId,
      });
      if (!existingPost)
        return res.status(404).send({ error: "Tuition post not found" });

      if (existingPost.userEmail !== fbEmail)
        return res.status(403).send({ error: "Forbidden. Not your post." });

      // Delete related applications to prevent orphan records
      await tuitionApplicationsCollection.deleteMany({ tuitionPostId: postId });

      // Delete the tuition post
      const result = await tuitionPostsCollection.deleteOne({ _id: postId });

      res.send({
        message: "Tuition post and related applications deleted successfully",
        deletedCount: result.deletedCount,
      });
    });

    /* =========================================================
       APPLICATIONS APIs
    ========================================================== */
    // GET all applications
    app.get("/applications", verifyFBToken, async (req, res) => {
      const studentEmail = req.query.studentEmail;
      if (!studentEmail)
        return res.status(400).send({ error: "studentEmail required" });

      try {
        const pipeline = [
          { $match: { userEmail: studentEmail } },

          {
            $lookup: {
              from: "tuitionApplications",
              localField: "_id",
              foreignField: "tuitionPostId",
              as: "applications",
            },
          },

          { $unwind: "$applications" },

          {
            $project: {
              _id: "$applications._id",
              applicationCode: "$applications.applicationCode",

              // tutor info
              tutorName: "$applications.tutorName",
              tutorEmail: "$applications.tutorEmail",
              tutorPhoto: "$applications.tutorPhoto",

              qualifications: "$applications.qualifications",
              experience: "$applications.experience",
              expectedSalary: "$applications.expectedSalary",
              status: "$applications.status",
              createdAt: "$applications.createdAt",

              // tuition info
              tuitionPostId: "$_id",
              tuitionCode: "$tuitionCode",
              tuitionTitle: "$subject",
              classLevel: "$classLevel",
              location: "$location",
            },
          },

          { $sort: { createdAt: -1 } },
        ];

        const result = await tuitionPostsCollection
          .aggregate(pipeline)
          .toArray();
        res.send(result);
      } catch (err) {
        res.status(500).send({ error: "Server error" });
      }
    });

    // GET all applications created by the logged-in tutor
    app.get(
      "/applications/my-applications",
      verifyFBToken,
      async (req, res) => {
        const fbEmail = req.user?.email;

        if (!fbEmail) {
          return res.status(401).send({ error: "Unauthorized" });
        }

        const result = await tuitionApplicationsCollection
          .aggregate([
            {
              $match: { tutorEmail: fbEmail },
            },
            // JOIN tuition post data
            {
              $lookup: {
                from: "tuitionPosts", // collection name
                localField: "tuitionPostId", // field in applications
                foreignField: "_id", // field in tuitionPosts
                as: "tuitionPost",
              },
            },
            {
              $unwind: {
                path: "$tuitionPost",
                preserveNullAndEmptyArrays: true,
              },
            },
            {
              $sort: { createdAt: -1 },
            },
          ])
          .toArray();
        res.send(result);
      }
    );

    // POST /applications - Create Tutor Application
    app.post("/applications", verifyFBToken, async (req, res) => {
      try {
        const { tuitionPostId, qualifications, experience, expectedSalary } =
          req.body;

        const fbEmail = req.user.email;
        const dbUser = await usersCollection.findOne({ email: fbEmail });

        if (!dbUser || dbUser.role !== "tutor")
          return res.status(403).send({ error: "Only tutors can apply" });

        if (!tuitionPostId || !qualifications || !experience || !expectedSalary)
          return res.status(400).send({ error: "Missing required fields" });

        let tuitionPostObjectId;
        try {
          tuitionPostObjectId = new ObjectId(tuitionPostId);
        } catch {
          return res.status(400).send({ error: "Invalid tuitionPostId" });
        }

        // Prevent duplicate application
        const exists = await tuitionApplicationsCollection.findOne({
          tuitionPostId: tuitionPostObjectId,
          tutorEmail: fbEmail,
        });
        if (exists)
          return res
            .status(409)
            .send({ error: "Already applied to this tuition" });

        const appCode = await getNextCode("applicationCode", "TA");

        const newApplication = {
          applicationCode: appCode,
          tuitionPostId: tuitionPostObjectId,
          tutorName: dbUser.name,
          tutorEmail: dbUser.email,
          tutorPhoto: dbUser.photoURL || null,
          qualifications,
          experience,
          expectedSalary: Number(expectedSalary),
          status: "pending",
          createdAt: new Date(),
        };

        const result = await tuitionApplicationsCollection.insertOne(
          newApplication
        );

        res.send({
          success: true,
          message: "Application submitted successfully",
          applicationId: result.insertedId,
          applicationCode: appCode,
        });
      } catch (err) {
        if (err.code === 11000) {
          // Mongo duplicate key error
          return res
            .status(409)
            .send({ error: "Duplicate application code, please try again" });
        }
        console.error(err);
        res.status(500).send({ error: "Internal server error" });
      }
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

    // PATCH - Tutor edits their own application fields
    app.patch(
      "/applications/tutor-update/:id",
      verifyFBToken,
      async (req, res) => {
        const appId = req.params.id;
        const fbEmail = req.user.email;

        const { qualifications, experience, expectedSalary } = req.body;

        const application = await tuitionApplicationsCollection.findOne({
          _id: new ObjectId(appId),
        });

        if (!application) {
          return res.status(404).send({ error: "Application not found" });
        }

        // ensure tutor is updating THEIR OWN application
        if (application.tutorEmail !== fbEmail) {
          return res
            .status(403)
            .send({ error: "You are not allowed to edit this application" });
        }

        const updatedFields = {
          qualifications,
          experience,
          expectedSalary: Number(expectedSalary),
          updatedAt: new Date(),
        };

        const result = await tuitionApplicationsCollection.updateOne(
          { _id: new ObjectId(appId) },
          { $set: updatedFields }
        );

        res.send(result);
      }
    );

    // DELETE - Tutor Deletes their own application
    app.delete("/applications/:id", verifyFBToken, async (req, res) => {
      const appId = req.params.id;
      const fbEmail = req.user.email;

      // Find the application
      const application = await tuitionApplicationsCollection.findOne({
        _id: new ObjectId(appId),
      });

      if (!application) {
        return res.status(404).send({ error: "Application not found" });
      }

      // Ownership check
      if (application.tutorEmail !== fbEmail) {
        return res
          .status(403)
          .send({ error: "You are not allowed to delete this application" });
      }

      // Delete the application
      const query = { _id: new ObjectId(appId) };
      const result = await tuitionApplicationsCollection.deleteOne(query);
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
