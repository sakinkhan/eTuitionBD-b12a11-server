const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const app = express();
require("dotenv").config();
const stripe = require("stripe")(process.env.STRIPE_SECRET);
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
    const paymentCollection = db.collection("payments");

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
          { role: { $regex: searchText, $options: "i" } },
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
      // Check if user already exists
      const existingUser = await usersCollection.findOne({ email: user.email });
      if (existingUser) {
        return res.status(200).send(existingUser);
      }
      const newUser = {
        ...user,
        role: user.role || "student",
        createdAt: new Date(),
      };
      const result = await usersCollection.insertOne(newUser);
      res.send(result);
    });

    // PATCH / Update user info:
    app.patch("/users/:id", verifyFBToken, async (req, res) => {
      const id = req.params.id;
      const { name, phone, role, photoURL, verified, isAdmin } = req.body;

      const query = { _id: new ObjectId(id) };
      const userToUpdate = await usersCollection.findOne(query);
      if (!userToUpdate)
        return res.status(404).send({ message: "User not found" });

      const requester = await usersCollection.findOne({
        email: req.user.email,
      });

      if (!requester) {
        return res.status(401).send({ message: "Unauthorized" });
      }

      const requesterIsAdmin = requester.isAdmin === true;
      const isSelf = req.user.email === userToUpdate.email;

      // Non-admin cannot update others
      if (!requesterIsAdmin && !isSelf) {
        return res
          .status(403)
          .send({ message: "Forbidden: cannot update other users" });
      }

      const updateFields = {};

      // Everyone (admin or self) can update their basic info
      if (name) updateFields.name = name;
      if (phone) updateFields.phone = phone;
      if (photoURL) updateFields.photoURL = photoURL;

      // Admin-only fields
      if (requesterIsAdmin) {
        if (typeof isAdmin === "boolean") updateFields.isAdmin = isAdmin;
        if (role) updateFields.role = role;
        if (typeof verified === "boolean") updateFields.verified = verified;
      } else {
        // Block non-admin from updating admin-only fields
        if (
          typeof isAdmin !== "undefined" ||
          typeof verified !== "undefined" ||
          role
        ) {
          return res.status(403).send({ message: "Forbidden: admin only" });
        }
      }

      const result = await usersCollection.updateOne(query, {
        $set: updateFields,
      });
      res.send(result);
    });

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
            { tuitionCode: { $regex: search, $options: "i" } },
            { contactEmail: { $regex: search, $options: "i" } },
            { status: { $regex: search, $options: "i" } },
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
          status: "pending",
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
      console.log("User details", req.user.isAdmin);

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
        status,
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
      if (status && ["approved", "rejected"].includes(status)) {
        updatedFields.status = status;
      }

      updatedFields.updatedAt = new Date();

      const result = await tuitionPostsCollection.findOneAndUpdate(
        { _id: postId },
        { $set: updatedFields },
        { returnDocument: "after" }
      );
      res.send({
        message: "Tuition post updated successfully",
        updatedPost: result.value,
      });
    });
    // PATCH /tuition-posts/admin/:id
    // Only admins can access
    app.patch(
      "/tuition-posts/admin/:id",
      verifyFBToken,
      verifyAdmin(usersCollection),
      async (req, res) => {
        const { id } = req.params;

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

        const { status } = req.body;
        if (!status || !["approved", "rejected"].includes(status)) {
          return res.status(400).send({
            error: "Invalid status. Must be 'approved' or 'rejected'.",
          });
        }

        const result = await tuitionPostsCollection.findOneAndUpdate(
          { _id: postId },
          { $set: { status, updatedAt: new Date() } },
          { returnDocument: "after" }
        );

        res.send({
          message: `Tuition post ${status} successfully`,
          updatedPost: result.value,
        });
      }
    );

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
      try {
        const studentEmail = req.user.email;
        const search = req.query.search?.trim();

        const pipeline = [
          // 1. Only this student's tuition posts
          { $match: { userEmail: studentEmail } },

          // 2. Join tutor applications
          {
            $lookup: {
              from: "tuitionApplications",
              localField: "_id",
              foreignField: "tuitionPostId",
              as: "applications",
            },
          },

          { $unwind: "$applications" },

          // 3. Shape final output
          {
            $project: {
              _id: "$applications._id",
              applicationCode: "$applications.applicationCode",

              tutorName: "$applications.tutorName",
              tutorEmail: "$applications.tutorEmail",
              tutorPhoto: "$applications.tutorPhoto",

              qualifications: "$applications.qualifications",
              experience: "$applications.experience",
              expectedSalary: "$applications.expectedSalary",
              status: "$applications.status",
              createdAt: "$applications.createdAt",

              tuitionPostId: "$_id",
              tuitionCode: "$tuitionCode",
              subject: "$subject",
              classLevel: "$classLevel",
              location: "$location",
              tuitionTitle: {
                $concat: [
                  "$subject",
                  " - Class: ",
                  "$classLevel",
                  " - ",
                  "$location",
                ],
              },
              studentEmail: "$userEmail",
            },
          },

          // 4. Search filter
          ...(search
            ? [
                {
                  $match: {
                    $or: [
                      { tutorName: { $regex: search, $options: "i" } },
                      { tuitionCode: { $regex: search, $options: "i" } },
                      { status: { $regex: search, $options: "i" } },
                    ],
                  },
                },
              ]
            : []),

          // 5. Sort
          { $sort: { createdAt: -1 } },
        ];

        const result = await tuitionPostsCollection
          .aggregate(pipeline)
          .toArray();

        res.send(result);
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: "Server error" });
      }
    });

    // GET all applications created by the logged-in tutor
    app.get(
      "/applications/my-applications",
      verifyFBToken,
      async (req, res) => {
        try {
          const tutorEmail = req.user.email;
          const search = req.query.search?.trim();

          const pipeline = [
            // 1. Only this tutor's applications
            {
              $match: { tutorEmail },
            },

            // 2. Join tuition post
            {
              $lookup: {
                from: "tuitionPosts",
                localField: "tuitionPostId",
                foreignField: "_id",
                as: "tuitionPost",
              },
            },

            {
              $unwind: {
                path: "$tuitionPost",
                preserveNullAndEmptyArrays: true,
              },
            },

            // 3. response structure
            {
              $project: {
                _id: 1,
                applicationCode: 1,
                tutorEmail: 1,
                tutorName: 1,
                tutorPhoto: 1,
                qualifications: 1,
                experience: 1,
                expectedSalary: 1,
                status: 1,
                createdAt: 1,

                tuitionPostId: "$tuitionPost._id",
                tuitionCode: "$tuitionPost.tuitionCode",
                subject: "$tuitionPost.subject",
                classLevel: "$tuitionPost.classLevel",
                location: "$tuitionPost.location",
                budget: "$tuitionPost.budget",
                studentEmail: "$tuitionPost.userEmail",
                tuitionTitle: {
                  $concat: [
                    "$tuitionPost.subject",
                    " - Class: ",
                    "$tuitionPost.classLevel",
                    " - ",
                    "$tuitionPost.location",
                  ],
                },
              },
            },

            // 4. Search filter
            ...(search
              ? [
                  {
                    $match: {
                      $or: [
                        { applicationCode: { $regex: search, $options: "i" } },
                        { subject: { $regex: search, $options: "i" } },
                        { status: { $regex: search, $options: "i" } },
                        { location: { $regex: search, $options: "i" } },
                      ],
                    },
                  },
                ]
              : []),

            // 5. sort latest first by default
            { $sort: { createdAt: -1 } },
          ];

          const result = await tuitionApplicationsCollection
            .aggregate(pipeline)
            .toArray();

          res.send(result);
        } catch (err) {
          console.error(err);
          res.status(500).send({ error: "Server error" });
        }
      }
    );

    // POST /applications - Create Tutor Application
    app.post("/applications", verifyFBToken, async (req, res) => {
      try {
        const { tuitionPostId, qualifications, experience, expectedSalary } =
          req.body;

        const fbEmail = req.user.email;
        // Verify tutor
        const dbUser = await usersCollection.findOne({ email: fbEmail });
        if (!dbUser || dbUser.role !== "tutor")
          return res.status(403).send({ error: "Only tutors can apply" });

        // Validate fields
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

    //PATCH - Reject applications by students
    app.patch("/applications/reject/:id", verifyFBToken, async (req, res) => {
      const id = req.params.id;
      const appQuery = { _id: new ObjectId(id), status: "pending" };
      const updatedFields = {
        $set: {
          status: "rejected",
          rejectedAt: new Date(),
        },
      };
      const result = await tuitionApplicationsCollection.updateOne(
        appQuery,
        updatedFields
      );
      if (result.matchedCount === 0) {
        return res.status(404).send({
          success: false,
          message: "Application not found or already processed",
        });
      }
      res.send(result);
    });

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

    /* =========================================================
       PAYMENT Related APIs
    ========================================================== */
    // POST payment checkout session
    app.post("/payment-checkout-session", async (req, res) => {
      const paymentInfo = req.body;
      // console.log("inside the checkout-PaymentInfo:", paymentInfo);
      const amount = parseInt(paymentInfo.expectedSalary) * 100;

      const session = await stripe.checkout.sessions.create({
        line_items: [
          {
            price_data: {
              currency: "BDT",
              unit_amount: amount,
              product_data: {
                name: `Payment to "${paymentInfo.tutorName}" for Tuition: ${paymentInfo.tuitionTitle}`,
              },
            },
            quantity: 1,
          },
        ],
        customer_email: paymentInfo.studentEmail,
        mode: "payment",
        metadata: {
          tuitionPostId: paymentInfo.tuitionPostId,
          tutorEmail: paymentInfo.tutorEmail,
          tuitionCode: paymentInfo.tuitionCode,
          tuitionTitle: paymentInfo.tuitionTitle,
        },
        success_url: `${process.env.SITE_DOMAIN}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.SITE_DOMAIN}/dashboard/payment-cancelled`,
      });
      res.send({ url: session.url });
    });

    // PATCH Verify Payment Success
    app.patch("/verify-payment-success", async (req, res) => {
      try {
        const sessionId = req.query.session_id;
        if (!sessionId) {
          return res
            .status(400)
            .send({ success: false, message: "Missing session_id" });
        }

        const session = await stripe.checkout.sessions.retrieve(sessionId);

        if (session.payment_status !== "paid") {
          return res.send({
            success: false,
            message: "Payment not completed",
          });
        }

        const { tuitionPostId, tutorEmail, tuitionTitle, tuitionCode } =
          session.metadata || {};

        if (!tuitionPostId || !tutorEmail) {
          return res
            .status(400)
            .send({ success: false, message: "Invalid session metadata" });
        }

        const tuitionPostObjectId = new ObjectId(tuitionPostId);
        const paidAt = new Date();

        /* -------------------- 1. Update tuition post -------------------- */
        const tuitionUpdateResult = await tuitionPostsCollection.updateOne(
          { _id: tuitionPostObjectId },
          {
            $set: {
              status: "approved & paid",
              paidAt,
            },
          }
        );

        /* -------------------- 2. Approve selected tutor -------------------- */
        const applicationUpdateResult =
          await tuitionApplicationsCollection.updateOne(
            {
              tuitionPostId: tuitionPostObjectId,
              tutorEmail,
            },
            {
              $set: { status: "approved & paid" },
            }
          );

        /* -------------------- 3. Reject other pending tutors -------------------- */
        const rejectOthersUpdate =
          await tuitionApplicationsCollection.updateMany(
            {
              tuitionPostId: tuitionPostObjectId,
              status: "pending",
              tutorEmail: { $ne: tutorEmail },
            },
            {
              $set: { status: "rejected" },
            }
          );

        /* -------------------- 4. Save payment history -------------------- */
        const fullTransactionId = session.payment_intent;
        const displayTransactionId = `ETB-${fullTransactionId
          .slice(-8)
          .toUpperCase()}`;

        const existingPayment = await paymentCollection.findOne({
          transactionId: fullTransactionId,
        });

        let paymentResult = null;

        if (!existingPayment) {
          paymentResult = await paymentCollection.insertOne({
            tuitionPostId: tuitionPostObjectId,
            tuitionTitle: tuitionTitle || null,
            tuitionCode: tuitionCode || null,

            tutorEmail,
            customer_email: session.customer_email,

            amount: session.amount_total / 100,
            currency: session.currency,

            transactionId: fullTransactionId,
            displayTransactionId,
            paymentStatus: session.payment_status,

            paidAt,
            createdAt: paidAt,
          });
        }

        return res.send({
          success: true,
          message: "Payment verified, tutor approved, others rejected.",
          tuitionUpdateResult,
          applicationUpdateResult,
          rejectOthersUpdate,
          paymentResult,
        });
      } catch (error) {
        console.error("Verify payment error:", error);
        res
          .status(500)
          .send({ success: false, message: "Internal server error" });
      }
    });

    // GET payments for Payment History
    app.get("/payments", verifyFBToken, async (req, res) => {
      try {
        // const email = req.user.email;
        const fbEmail = req.user?.email;
        console.log("in the payments get api", fbEmail);

        const payments = await paymentCollection
          .find({ customer_email: fbEmail })
          .sort({ paidAt: -1 })
          .toArray();

        res.send(payments);
      } catch (error) {
        console.error("Fetch payment history error:", error);
        res.status(500).send({ message: "Failed to fetch payment history" });
      }
    });

    // //GET tutor ongoing tuitions
    // app.get("/tutor/ongoing-tuitions", verifyFBToken, async (req, res) => {
    //   const tutorEmail = req.user.email;
    //   const query = {
    //     tutorEmail: tutorEmail,
    //     status: "approved & paid",
    //   };
    //   const cursor = tuitionApplicationsCollection
    //     .find(query)
    //     .sort({ createdAt: -1 });
    //   const result = await cursor.toArray();
    //   res.send(result);
    // });

    // GET tutor ongoing tuitions
    app.get("/tutor/ongoing-tuitions", verifyFBToken, async (req, res) => {
      const tutorEmail = req.user.email;
      const cursor = tuitionApplicationsCollection.aggregate([
        // 1. match tutor + status: approved & paid
        {
          $match: {
            tutorEmail: tutorEmail,
            status: "approved & paid",
          },
        },
        // 2. join with payments collection
        {
          $lookup: {
            from: "payments",
            localField: "tuitionPostId",
            foreignField: "tuitionPostId",
            as: "payment",
          },
        },
        // 3. unwind payment array
        {
          $unwind: {
            path: "$payment",
            preserveNullAndEmptyArrays: false,
          },
        },
        // 4. ensure payment is paid
        {
          $match: {
            "payment.paymentStatus": "paid",
          },
        },
        // 5. Join with users collection to get student info
        {
          $lookup: {
            from: "users",
            localField: "payment.customer_email",
            foreignField: "email",
            as: "student",
          },
        },
        // 6. unwind student array
        {
          $unwind: {
            path: "$student",
            preserveNullAndEmptyArrays: true,
          },
        },

        // 5. final response structure
        {
          $project: {
            _id: 1,
            applicationCode: 1,
            tuitionPostId: 1,
            status: 1,
            createdAt: 1,
            // from payments
            tuitionTitle: "$payment.tuitionTitle",
            salary: "$payment.amount",
            // from students
            studentName: "$student.name",
            studentEmail: "$student.email",
            studentPhone: "$student.phone",
          },
        },
        // 6️. Sort newest first
        {
          $sort: { createdAt: -1 },
        },
      ]);
      const ongoingTuitionsResult = await cursor.toArray();
      res.send(ongoingTuitionsResult);
    });

    // GET Tutor revenue history
    app.get("/tutor/revenue", verifyFBToken, async (req, res) => {
      const tutorEmail = req.user.email;
      const query = {
        tutorEmail: tutorEmail,
        paymentStatus: "paid",
      };
      const cursor = paymentCollection.find(query).sort({ paidAt: -1 });
      const result = await cursor.toArray();
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
