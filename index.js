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
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).send({ message: "No authorization header" });
  }

  if (!authHeader.startsWith("Bearer ")) {
    return res.status(401).send({ message: "Invalid auth format" });
  }

  const idToken = authHeader.split(" ")[1];

  if (!idToken || idToken === "null" || idToken === "undefined") {
    return res.status(401).send({ message: "Invalid token" });
  }

  try {
    const decoded = await admin.auth().verifyIdToken(idToken);

    req.user = {
      uid: decoded.uid,
      email: decoded.email?.toLowerCase(),
    };

    next();
  } catch (err) {
    console.error("verifyFBToken error:", err.message);
    return res.status(401).send({ message: "Token verification failed" });
  }
};

const verifyAdmin = (usersCollection) => async (req, res, next) => {
  try {
    const fbEmail = req.user?.email;
    if (!fbEmail) return res.status(401).send({ message: "unauthorized" });

    const user = await usersCollection.findOne({
      email: fbEmail,
      isDeleted: { $ne: true },
    });
    if (!user || !user.isAdmin) {
      return res.status(403).send({ message: "forbidden access: admin only" });
    }
    next();
  } catch (err) {
    console.error("verifyAdmin error", err);
    res.status(500).send({ message: "server error" });
  }
};

// 🔎 TEMP DEBUG LOGGER (place it HERE)
app.use((req, res, next) => {
  console.log("➡️", req.method, req.originalUrl);
  next();
});

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
    const tutorCollection = db.collection("tutors");
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
    await tuitionApplicationsCollection.createIndex(
      { tuitionPostId: 1, tutorId: 1 },
      { unique: true }
    );

    // Code generator
    const getNextCode = async (name, prefix) => {
      const counter = await countersCollection.findOneAndUpdate(
        { name },
        { $inc: { value: 1 } },
        { upsert: true, returnDocument: "after" }
      );

      return `${prefix}-${counter.value}`;
    };

    /* =========================================================
       USER RELATED APIs
    ========================================================== */
    // GET all users (public)
    app.get("/public-users", async (req, res) => {
      try {
        const search = req.query.search?.trim();
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;

        const query = { isDeleted: { $ne: true } };

        if (search) {
          query.$or = [
            { name: { $regex: search, $options: "i" } },
            { email: { $regex: search, $options: "i" } },
            { role: { $regex: search, $options: "i" } },
          ];
        }

        // Only return tutors for public display
        query.role = "tutor";

        const total = await usersCollection.countDocuments(query);

        const users = await usersCollection
          .find(query)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .toArray();

        res.send({
          success: true,
          page,
          limit,
          total,
          users,
        });
      } catch (err) {
        console.error("GET /public-users error:", err);
        res
          .status(500)
          .send({ success: false, message: "Failed to fetch users" });
      }
    });

    // GET current user
    app.get("/users/me", verifyFBToken, async (req, res) => {
      try {
        const email = req.user?.email;
        if (!email) {
          return res.status(401).send({ message: "Unauthorized" });
        }

        const user = await usersCollection.findOne(
          { email, isDeleted: { $ne: true } },
          {
            projection: {
              role: 1,
              isAdmin: 1,
              profileCompleted: 1,
              name: 1,
              photoURL: 1,
            },
          }
        );

        if (!user) {
          return res.status(404).send({ message: "User not found" });
        }

        res.send({
          role: user.role,
          isAdmin: !!user.isAdmin,
          profileCompleted: !!user.profileCompleted,
          name: user.name || null,
          photoURL: user.photoURL || null,
        });
      } catch (err) {
        console.error("GET /users/me error:", err);
        res.status(500).send({ message: "Server error" });
      }
    });

    // GET single user by email
    app.get("/users/:email", verifyFBToken, async (req, res) => {
      try {
        const email = req.params.email?.trim().toLowerCase(); // normalize email
        if (!email) {
          return res
            .status(400)
            .send({ success: false, message: "Invalid email" });
        }

        // Only fetch users that are not soft-deleted
        const user = await usersCollection.findOne({
          email,
          isDeleted: { $ne: true },
        });

        if (!user) {
          return res
            .status(404)
            .send({ success: false, message: "User not found" });
        }

        res.send({ success: true, user });
      } catch (error) {
        console.error("GET /users/:email error:", error);
        res
          .status(500)
          .send({ success: false, message: "Internal Server Error" });
      }
    });

    // GET all users
    app.get("/users", verifyFBToken, async (req, res) => {
      try {
        const search = req.query.search?.trim();
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;

        const query = { isDeleted: { $ne: true } };

        if (search) {
          query.$or = [
            { name: { $regex: search, $options: "i" } },
            { email: { $regex: search, $options: "i" } },
            { role: { $regex: search, $options: "i" } },
          ];
        }

        const total = await usersCollection.countDocuments(query);
        const users = await usersCollection
          .find(query)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .toArray();

        res.send({
          success: true,
          page,
          limit,
          total,
          users,
        });
      } catch (err) {
        console.error("GET /users error:", err);
        res
          .status(500)
          .send({ success: false, message: "Failed to fetch users" });
      }
    });

    // POST /users - Create or update user
    app.post("/users", verifyFBToken, async (req, res) => {
      try {
        const { name, email, role, phone, photoURL } = req.body;

        if (!name || !email) {
          return res
            .status(400)
            .send({ success: false, message: "Name and email are required" });
        }

        const normalizedEmail = email.trim().toLowerCase();

        // Fetch existing user (including deleted check)
        const existingUser = await usersCollection.findOne({
          email: normalizedEmail,
          isDeleted: { $ne: true },
        });

        // Decide role safely
        const safeRole =
          existingUser?.role || (role === "tutor" ? "tutor" : "student");

        const updateDoc = {
          $set: {
            name: name.trim(),
            phone: phone ?? existingUser?.phone ?? null,
            photoURL: photoURL ?? existingUser?.photoURL ?? null,
            updatedAt: new Date(),
          },
          $setOnInsert: {
            email: normalizedEmail,
            role: safeRole,
            isAdmin: false,
            isVerified: false,
            profileCompleted: safeRole === "tutor" ? false : true,
            isDeleted: false,
            createdAt: new Date(),
          },
        };

        const result = await usersCollection.updateOne(
          { email: normalizedEmail },
          updateDoc,
          { upsert: true }
        );

        const user = await usersCollection.findOne({ email: normalizedEmail });

        res.send({
          success: true,
          user,
          created: result.upsertedCount === 1,
          message: result.upsertedCount
            ? "User created successfully"
            : "User updated successfully",
        });
      } catch (err) {
        console.error("POST /users error:", err);
        res
          .status(500)
          .send({ success: false, message: "Internal server error" });
      }
    });

    // PATCH /users/:id - Update user info
    app.patch("/users/:id", verifyFBToken, async (req, res) => {
      try {
        const id = req.params.id;
        if (!ObjectId.isValid(id)) {
          return res
            .status(400)
            .send({ success: false, message: "Invalid user ID" });
        }

        const { name, phone, role, photoURL, isVerified, isAdmin } = req.body;

        const query = { _id: new ObjectId(id), isDeleted: { $ne: true } };
        const userToUpdate = await usersCollection.findOne(query);
        if (!userToUpdate) {
          return res
            .status(404)
            .send({ success: false, message: "User not found" });
        }

        const requester = await usersCollection.findOne({
          email: req.user.email,
          isDeleted: { $ne: true },
        });
        if (!requester) {
          return res
            .status(401)
            .send({ success: false, message: "Unauthorized" });
        }

        const requesterIsAdmin = !!requester.isAdmin;
        const isSelf = req.user.email === userToUpdate.email;

        // Non-admin cannot update others
        if (!requesterIsAdmin && !isSelf) {
          return res.status(403).send({
            success: false,
            message: "Forbidden: cannot update other users",
          });
        }

        const updateFields = {};

        // Everyone can update basic info
        if (name !== undefined) updateFields.name = name.trim();
        if (phone !== undefined) updateFields.phone = phone.trim();
        if (photoURL !== undefined) updateFields.photoURL = photoURL.trim();

        // Admin-only fields
        if (requesterIsAdmin) {
          if (typeof isAdmin === "boolean") updateFields.isAdmin = isAdmin;
          if (role) updateFields.role = role;
          if (typeof isVerified === "boolean")
            updateFields.isVerified = isVerified;
        } else {
          if (
            typeof isAdmin !== "undefined" ||
            typeof isVerified !== "undefined" ||
            role
          ) {
            return res
              .status(403)
              .send({ success: false, message: "Forbidden: admin only" });
          }
        }

        if (Object.keys(updateFields).length === 0) {
          return res
            .status(400)
            .send({ success: false, message: "No valid fields to update" });
        }

        updateFields.updatedAt = new Date();

        const result = await usersCollection.updateOne(query, {
          $set: updateFields,
        });

        res.send({
          success: true,
          modifiedCount: result.modifiedCount,
          message: "User updated successfully",
        });
      } catch (err) {
        console.error("PATCH /users/:id error:", err);
        res
          .status(500)
          .send({ success: false, message: "Internal server error" });
      }
    });

    // PATCH /users/:id/admin - Update user admin status (admin-only)
    app.patch(
      "/users/:id/admin",
      verifyFBToken,
      verifyAdmin(usersCollection),
      async (req, res) => {
        try {
          const id = req.params.id;
          if (!ObjectId.isValid(id)) {
            return res
              .status(400)
              .send({ success: false, message: "Invalid user ID" });
          }

          const query = { _id: new ObjectId(id), isDeleted: { $ne: true } };
          const userToUpdate = await usersCollection.findOne(query);

          if (!userToUpdate) {
            return res
              .status(404)
              .send({ success: false, message: "User not found" });
          }

          const isAdmin = !!req.body.isAdmin;

          const result = await usersCollection.updateOne(query, {
            $set: { isAdmin, updatedAt: new Date() },
          });

          res.send({
            success: true,
            modifiedCount: result.modifiedCount,
            message: `User admin status updated to ${isAdmin}`,
          });
        } catch (err) {
          console.error("PATCH /users/:id/admin error:", err);
          res
            .status(500)
            .send({ success: false, message: "Internal server error" });
        }
      }
    );

    // DELETE /users/:id - Soft delete user (admin-only)
    app.delete(
      "/users/:id",
      verifyFBToken,
      verifyAdmin(usersCollection),
      async (req, res) => {
        try {
          const id = req.params.id;
          if (!ObjectId.isValid(id)) {
            return res
              .status(400)
              .send({ success: false, message: "Invalid user ID" });
          }

          const query = { _id: new ObjectId(id), isDeleted: { $ne: true } };
          const user = await usersCollection.findOne(query);

          if (!user) {
            return res.status(404).send({
              success: false,
              message: "User not found or already deleted",
            });
          }

          const result = await usersCollection.updateOne(
            { _id: user._id },
            {
              $set: {
                isDeleted: true,
                deletedAt: new Date(),
                updatedAt: new Date(),
              },
            }
          );

          res.send({
            success: true,
            modifiedCount: result.modifiedCount,
            message: "User soft-deleted successfully",
          });
        } catch (err) {
          console.error("DELETE /users/:id error:", err);
          res
            .status(500)
            .send({ success: false, message: "Internal server error" });
        }
      }
    );

    /* =========================================================
       TUTOR related APIs
    ========================================================== */
    // POST /tutors - Create tutor profile (first time)
    app.post("/tutors", verifyFBToken, async (req, res) => {
      try {
        const fbEmail = req.user?.email;
        if (!fbEmail) {
          return res.status(401).send({ message: "Unauthorized" });
        }

        const user = await usersCollection.findOne({
          email: fbEmail,
          isDeleted: { $ne: true },
        });

        if (!user || user.role !== "tutor") {
          return res
            .status(403)
            .send({ message: "Only tutors can create profile" });
        }

        // Prevent duplicate profile
        const existingProfile = await tutorCollection.findOne({
          userId: user._id,
        });

        if (existingProfile) {
          return res
            .status(409)
            .send({ message: "Tutor profile already exists" });
        }

        const { qualifications, experience, subjects, expectedSalary, bio } =
          req.body;

        if (
          !qualifications ||
          !experience ||
          !subjects ||
          !expectedSalary ||
          !bio
        ) {
          return res.status(400).send({ message: "Missing required fields" });
        }

        const now = new Date();

        const tutorProfile = {
          userId: user._id,
          email: user.email,
          name: user.name,

          qualifications,
          experience,
          subjects: Array.isArray(subjects)
            ? subjects
            : subjects.split(",").map((s) => s.trim()),
          expectedSalary: Number(expectedSalary),
          bio,

          tutorStatus: "pending", // admin approval required
          isActive: true,

          createdAt: now,
          updatedAt: now,
        };

        const result = await tutorCollection.insertOne(tutorProfile);

        // Mark profile as completed in users
        await usersCollection.updateOne(
          { _id: user._id },
          {
            $set: {
              profileCompleted: true,
              updatedAt: now,
            },
          }
        );

        res.send({
          success: true,
          message: "Tutor profile created successfully",
          tutorId: result.insertedId,
        });
      } catch (err) {
        console.error("POST /tutors error:", err);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    // GET /tutors/me - Get logged-in tutor profile
    app.get("/tutors/me", verifyFBToken, async (req, res) => {
      try {
        const fbEmail = req.user?.email;
        if (!fbEmail) {
          return res.status(401).send({ message: "Unauthorized" });
        }

        const user = await usersCollection.findOne({
          email: fbEmail,
          isDeleted: { $ne: true },
        });

        if (!user || user.role !== "tutor") {
          return res.status(403).send({ message: "Tutor access only" });
        }

        const tutorProfile = await tutorCollection.findOne({
          userId: user._id,
        });

        if (!tutorProfile) {
          return res.status(404).send({
            message: "Tutor profile not found",
            profileCompleted: false,
          });
        }

        res.send({
          success: true,
          profileCompleted: true,
          tutor: tutorProfile,
        });
      } catch (err) {
        console.error("GET /tutors/me error:", err);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    // PATCH /tutors/me - Update tutor profile
    app.patch("/tutors/me", verifyFBToken, async (req, res) => {
      try {
        const fbEmail = req.user?.email;
        if (!fbEmail) {
          return res.status(401).send({ message: "Unauthorized" });
        }

        const user = await usersCollection.findOne({
          email: fbEmail,
          isDeleted: { $ne: true },
        });

        if (!user || user.role !== "tutor") {
          return res.status(403).send({ message: "Tutor access only" });
        }

        const tutorProfile = await tutorCollection.findOne({
          userId: user._id,
        });

        if (!tutorProfile) {
          return res.status(404).send({
            message: "Tutor profile not found",
          });
        }

        const { qualifications, experience, subjects, expectedSalary, bio } =
          req.body;

        const updateFields = {
          updatedAt: new Date(),
        };

        if (qualifications !== undefined)
          updateFields.qualifications = qualifications;

        if (experience !== undefined) updateFields.experience = experience;

        if (subjects !== undefined) {
          updateFields.subjects = Array.isArray(subjects)
            ? subjects
            : subjects.split(",").map((s) => s.trim());
        }

        if (expectedSalary !== undefined) {
          const salary = Number(expectedSalary);
          if (Number.isNaN(salary) || salary <= 0) {
            return res
              .status(400)
              .send({ message: "Expected salary must be a valid number" });
          }
          updateFields.expectedSalary = salary;
        }

        if (bio !== undefined) updateFields.bio = bio;

        // Nothing to update?
        if (Object.keys(updateFields).length === 1) {
          return res
            .status(400)
            .send({ message: "No valid fields provided for update" });
        }

        const result = await tutorCollection.updateOne(
          { userId: user._id },
          { $set: updateFields }
        );

        res.send({
          success: true,
          message: "Tutor profile updated successfully",
          modifiedCount: result.modifiedCount,
        });
      } catch (err) {
        console.error("PATCH /tutors/me error:", err);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    // GET /tutors/public - Public tutor listing
    app.get("/tutors/public", async (req, res) => {
      try {
        const search = req.query.search?.trim();
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;

        const pipeline = [
          // Only active tutors
          {
            $match: {
              isActive: true,
              tutorStatus: "approved",
            },
          },

          // Join users for name & photo
          {
            $lookup: {
              from: "users",
              localField: "userId",
              foreignField: "_id",
              as: "user",
            },
          },
          { $unwind: "$user" },

          // Exclude deleted users
          {
            $match: {
              "user.isDeleted": { $ne: true },
            },
          },

          // Search
          ...(search
            ? [
                {
                  $match: {
                    $or: [
                      { "user.name": { $regex: search, $options: "i" } },
                      { qualifications: { $regex: search, $options: "i" } },
                      { experience: { $regex: search, $options: "i" } },
                      { subjects: { $in: [new RegExp(search, "i")] } },
                    ],
                  },
                },
              ]
            : []),

          // Shape response
          {
            $project: {
              tutorId: "$_id",
              name: "$user.name",
              photoURL: "$user.photoURL",
              qualifications: 1,
              experience: 1,
              subjects: 1,
              expectedSalary: 1,
              bio: 1,
              createdAt: 1,
            },
          },

          { $sort: { createdAt: -1 } },
          { $skip: skip },
          { $limit: limit },
        ];

        const tutors = await tutorCollection.aggregate(pipeline).toArray();

        // Count (without pagination)
        const countPipeline = pipeline.filter(
          (stage) => !stage.$skip && !stage.$limit && !stage.$sort
        );
        countPipeline.push({ $count: "total" });

        const countResult = await tutorCollection
          .aggregate(countPipeline)
          .toArray();

        const total = countResult[0]?.total || 0;

        res.send({
          success: true,
          page,
          limit,
          total,
          tutors,
        });
      } catch (err) {
        console.error("GET /tutors/public error:", err);
        res.status(500).send({ message: "Failed to fetch tutors" });
      }
    });

    // GET /tutors/admin - Admin tutor management
    app.get(
      "/tutors/admin",
      verifyFBToken,
      verifyAdmin(usersCollection),
      async (req, res) => {
        try {
          const search = req.query.search?.trim();
          const page = parseInt(req.query.page) || 1;
          const limit = parseInt(req.query.limit) || 10;
          const skip = (page - 1) * limit;

          const pipeline = [
            {
              $lookup: {
                from: "users",
                localField: "userId",
                foreignField: "_id",
                as: "user",
              },
            },
            { $unwind: "$user" },

            {
              $match: {
                "user.isDeleted": { $ne: true },
              },
            },

            ...(search
              ? [
                  {
                    $match: {
                      $or: [
                        { "user.name": { $regex: search, $options: "i" } },
                        { "user.email": { $regex: search, $options: "i" } },
                        { subjects: { $in: [new RegExp(search, "i")] } },
                      ],
                    },
                  },
                ]
              : []),

            {
              $project: {
                tutorId: "$_id",
                name: "$user.name",
                email: "$user.email",
                photoURL: "$user.photoURL",

                qualifications: 1,
                experience: 1,
                subjects: 1,
                expectedSalary: 1,

                tutorStatus: { $ifNull: ["$tutorStatus", "pending"] },
                tutorApprovedAt: 1,
                createdAt: 1,
              },
            },

            { $sort: { createdAt: -1 } },
            { $skip: skip },
            { $limit: limit },
          ];

          const tutors = await tutorCollection.aggregate(pipeline).toArray();

          const countPipeline = pipeline.filter(
            (stage) => !stage.$skip && !stage.$limit && !stage.$sort
          );
          countPipeline.push({ $count: "total" });

          const countResult = await tutorCollection
            .aggregate(countPipeline)
            .toArray();

          res.send({
            success: true,
            page,
            limit,
            total: countResult[0]?.total || 0,
            tutors,
          });
        } catch (err) {
          console.error("GET /tutors/admin error:", err);
          res.status(500).send({ message: "Failed to fetch tutors" });
        }
      }
    );

    // GET /tutors/admin/:id - View full tutor profile (Admin)
    app.get(
      "/tutors/admin/:id",
      verifyFBToken,
      verifyAdmin(usersCollection),
      async (req, res) => {
        try {
          const tutorId = req.params.id;

          if (!ObjectId.isValid(tutorId)) {
            return res.status(400).send({ message: "Invalid tutor ID" });
          }

          const pipeline = [
            {
              $match: { _id: new ObjectId(tutorId) },
            },
            {
              $lookup: {
                from: "users",
                localField: "userId",
                foreignField: "_id",
                as: "user",
              },
            },
            { $unwind: "$user" },
            {
              $match: {
                "user.isDeleted": { $ne: true },
              },
            },
            {
              $project: {
                tutorId: "$_id",
                tutorStatus: { $ifNull: ["$tutorStatus", "pending"] },
                tutorApprovedAt: 1,

                qualifications: 1,
                experience: 1,
                subjects: 1,
                expectedSalary: 1,
                bio: 1,

                createdAt: 1,
                updatedAt: 1,

                user: {
                  name: "$user.name",
                  email: "$user.email",
                  phone: "$user.phone",
                  photoURL: "$user.photoURL",
                  createdAt: "$user.createdAt",
                },
              },
            },
          ];

          const result = await tutorCollection.aggregate(pipeline).toArray();

          if (!result.length) {
            return res.status(404).send({ message: "Tutor not found" });
          }

          res.send({
            success: true,
            tutor: result[0],
          });
        } catch (err) {
          console.error("GET /tutors/admin/:id error:", err);
          res.status(500).send({ message: "Internal server error" });
        }
      }
    );

    // PATCH /tutors/admin/verify/:id - Approve / Reject tutor
    app.patch(
      "/tutors/admin/verify/:id",
      verifyFBToken,
      verifyAdmin(usersCollection),
      async (req, res) => {
        try {
          const tutorId = req.params.id;
          const { tutorStatus } = req.body;

          // 1. Validate tutorId
          if (!ObjectId.isValid(tutorId)) {
            return res.status(400).send({
              success: false,
              message: "Invalid tutor ID",
            });
          }

          // 2. Validate tutorStatus
          const allowedStatuses = ["approved", "rejected"];
          if (!allowedStatuses.includes(tutorStatus)) {
            return res.status(400).send({
              success: false,
              message: "tutorStatus must be 'approved' or 'rejected'",
            });
          }

          // 3. Fetch tutor profile
          const tutor = await tutorCollection.findOne({
            _id: new ObjectId(tutorId),
          });

          if (!tutor) {
            return res.status(404).send({
              success: false,
              message: "Tutor not found",
            });
          }

          // 4. Update tutor status
          const updateDoc = {
            tutorStatus,
            tutorApprovedAt: tutorStatus === "approved" ? new Date() : null,
            updatedAt: new Date(),
          };

          await tutorCollection.updateOne(
            { _id: tutor._id },
            { $set: updateDoc }
          );

          res.send({
            success: true,
            message: `Tutor ${tutorStatus} successfully`,
          });
        } catch (err) {
          console.error("PATCH /tutors/admin/verify/:id error:", err);
          res.status(500).send({
            success: false,
            message: "Internal server error",
          });
        }
      }
    );

    // GET /tutors/:id - Tutor profile
    app.get("/tutors/:id", verifyFBToken, async (req, res) => {
      try {
        const tutorId = req.params.id;

        if (!ObjectId.isValid(tutorId)) {
          return res.status(400).send({ message: "Invalid tutor ID" });
        }

        // determine requester is admin
        const requester = await usersCollection.findOne({
          email: req.user.email,
          isDeleted: { $ne: true },
        });
        const isAdmin = !!requester?.isAdmin;

        const matchStage = {
          _id: new ObjectId(tutorId),
          isActive: true,
        };

        // public/student/tutor users should only see approved tutors
        if (!isAdmin) {
          matchStage.tutorStatus = "approved";
        }

        const pipeline = [
          { $match: matchStage },

          {
            $lookup: {
              from: "users",
              localField: "userId",
              foreignField: "_id",
              as: "user",
            },
          },

          { $unwind: "$user" },

          { $match: { "user.isDeleted": { $ne: true } } },

          {
            $project: {
              _id: 1,

              name: "$user.name",
              email: "$user.email",
              phone: "$user.phone",
              photoURL: "$user.photoURL",

              qualifications: 1,
              experience: 1,
              subjects: 1,
              expectedSalary: 1,
              bio: 1,

              isVerified: "$user.isVerified",
              isActive: 1,
              createdAt: 1,
            },
          },
        ];

        const result = await tutorCollection.aggregate(pipeline).toArray();

        if (!result.length) {
          return res.status(404).send({ message: "Tutor not found" });
        }

        res.send({
          success: true,
          tutor: result[0],
        });
      } catch (err) {
        console.error("GET /tutors/:id error:", err);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    /* =========================================================
       TUITION POSTS related APIs
    ========================================================== */
    // GET all tuition posts (public / latest first)
    app.get("/tuition-posts", async (req, res) => {
      try {
        const search = req.query.search?.trim() || "";
        const limit = parseInt(req.query.limit) || 20;
        const skip = parseInt(req.query.skip) || 0;

        const query = {
          status: "admin-approved",
          isDeleted: { $ne: true },
        };

        if (search) {
          query.$or = [
            { subject: { $regex: search, $options: "i" } },
            { classLevel: { $regex: search, $options: "i" } },
            { location: { $regex: search, $options: "i" } },
            { tuitionCode: { $regex: search, $options: "i" } },
          ];
        }

        const total = await tuitionPostsCollection.countDocuments(query);

        const posts = await tuitionPostsCollection
          .find(query)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .toArray();

        res.send({
          success: true,
          total,
          page: Math.floor(skip / limit) + 1,
          limit,
          posts,
        });
      } catch (err) {
        console.error("Error fetching public tuition posts:", err);
        res.status(500).send({ error: "Failed to fetch tuition posts" });
      }
    });

    // GET all my tuition posts (student view) with pagination
    app.get("/tuition-posts/my-posts", verifyFBToken, async (req, res) => {
      try {
        const fbEmail = req.user?.email;
        if (!fbEmail) {
          return res.status(400).send({ error: "Invalid authentication" });
        }

        const search = req.query.search?.trim();
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;

        // Base query: only own posts + not deleted
        const query = {
          studentEmail: fbEmail,
          isDeleted: { $ne: true },
        };

        // Optional search on safe fields
        if (search) {
          query.$or = [
            { subject: { $regex: search, $options: "i" } },
            { classLevel: { $regex: search, $options: "i" } },
            { location: { $regex: search, $options: "i" } },
            { tuitionCode: { $regex: search, $options: "i" } },
            { status: { $regex: search, $options: "i" } },
          ];
        }

        // Count total matching documents
        const total = await tuitionPostsCollection.countDocuments(query);

        // Get paginated results
        const tuitions = await tuitionPostsCollection
          .find(query)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .toArray();

        res.send({
          success: true,
          page,
          limit,
          total,
          tuitions,
        });
      } catch (err) {
        console.error("GET /tuition-posts/my-posts error:", err);
        res.status(500).send({
          success: false,
          message: "Failed to fetch your tuition posts",
        });
      }
    });

    // GET all tuition posts - Admin-only
    app.get(
      "/tuition-posts/admin-dashboard",
      verifyFBToken,
      verifyAdmin(usersCollection),
      async (req, res) => {
        try {
          const search = req.query.search?.trim() || "";
          const page = parseInt(req.query.page) || 1;
          const limit = parseInt(req.query.limit) || 20;
          const skip = (page - 1) * limit;

          const query = { isDeleted: { $ne: true } };

          if (search) {
            query.$or = [
              { subject: { $regex: search, $options: "i" } },
              { classLevel: { $regex: search, $options: "i" } },
              { location: { $regex: search, $options: "i" } },
              { tuitionCode: { $regex: search, $options: "i" } },
              { status: { $regex: search, $options: "i" } },
              { studentName: { $regex: search, $options: "i" } },
              { studentEmail: { $regex: search, $options: "i" } },
            ];
          }

          const total = await tuitionPostsCollection.countDocuments(query);

          const posts = await tuitionPostsCollection
            .find(query)
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .toArray();

          res.send({
            success: true,
            total,
            page,
            limit,
            posts,
          });
        } catch (err) {
          console.error("Error fetching admin tuition posts:", err);
          res.status(500).send({ error: "Failed to fetch tuition posts" });
        }
      }
    );

    // GET single tuition post by id
    app.get("/tuition-posts/:id", verifyFBToken, async (req, res) => {
      try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
          return res.status(400).send({ error: "Invalid tuition post ID" });
        }

        const postId = new ObjectId(id);

        const { email, role, isAdmin } = req.user;

        // Base condition: must not be deleted
        const query = {
          _id: postId,
          isDeleted: { $ne: true },
        };

        // ADMIN: full access
        if (!isAdmin) {
          if (role === "tutor") {
            // Tutors: ONLY admin-approved
            query.status = "admin-approved";
          }

          if (role === "student") {
            // Students: own posts (any status) OR approved posts
            query.$or = [{ userEmail: email }, { status: "admin-approved" }];
          }
        }

        const post = await tuitionPostsCollection.findOne(query);

        if (!post) {
          return res.status(404).send({ error: "Tuition post not found" });
        }

        res.send(post);
      } catch (err) {
        console.error("GET /tuition-posts/:id error:", err);
        res.status(500).send({ error: "Failed to fetch tuition post" });
      }
    });

    // POST /tuition-post - Create Tuition Post
    app.post("/tuition-post", verifyFBToken, async (req, res) => {
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

        // 1. Validate required fields
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

        // 2. Get student info
        const student = await usersCollection.findOne({ email: fbEmail });
        if (!student) {
          return res.status(404).send({ error: "Student not found" });
        }

        const now = new Date();
        let tuitionCode;
        let inserted = false;
        let insertResult;

        // 3. Loop to avoid duplicate tuitionCode
        while (!inserted) {
          try {
            tuitionCode = await getNextCode("tuitionCode", "TP");

            const newPost = {
              tuitionCode,
              studentId: student._id,
              studentEmail: fbEmail,
              studentName: student.name || "Unknown",

              subject,
              classLevel,
              location,
              budget: Number(budget),
              schedule: schedule || "",
              description,
              contactEmail,

              status: "admin-pending",
              isDeleted: false,
              deletedAt: null,

              applicationsCount: 0,
              pendingApplicationsCount: 0,

              // Timestamps
              createdAt: now,
              updatedAt: now,
              adminApprovedAt: null,
              tutorApprovedAt: null,
              paidAt: null,
              completedAt: null,
              cancelledAt: null,
            };

            insertResult = await tuitionPostsCollection.insertOne(newPost);
            inserted = true;
          } catch (err) {
            // Retry only if duplicate key on tuitionCode
            if (err.code === 11000) continue;
            throw err;
          }
        }

        res.send({
          success: true,
          insertedId: insertResult.insertedId,
          tuitionCode,
        });
      } catch (err) {
        console.error("POST /tuition-post error:", err);
        res.status(500).send({ error: "Internal server error" });
      }
    });

    // PATCH/edit tuition posts (Student only)
    app.patch("/tuition-posts/:id", verifyFBToken, async (req, res) => {
      try {
        const id = req.params.id;
        const fbEmail = req.user?.email;

        if (!fbEmail) {
          return res.status(400).send({ error: "Invalid authentication" });
        }

        // 1. Validate ObjectId
        if (!ObjectId.isValid(id)) {
          return res.status(400).send({ error: "Invalid tuition post ID" });
        }
        const postId = new ObjectId(id);

        // 2. Fetch existing post
        const existingPost = await tuitionPostsCollection.findOne({
          _id: postId,
        });
        if (!existingPost) {
          return res.status(404).send({ error: "Tuition post not found" });
        }

        // 3. Ownership check
        if (existingPost.userEmail !== fbEmail) {
          return res.status(403).send({ error: "Forbidden. Not your post." });
        }

        // 4. Soft-delete guard
        if (existingPost.isDeleted) {
          return res
            .status(400)
            .send({ error: "Cannot edit a withdrawn post" });
        }

        // 5. Status guard: cannot edit after tutor approval or payment
        const lockedStatuses = ["tutor-approved", "paid", "completed"];
        if (lockedStatuses.includes(existingPost.status)) {
          return res.status(400).send({
            error: "Cannot edit post after tutor approval or payment",
          });
        }

        // 6. Build updated fields (student cannot change status)
        const {
          subject,
          classLevel,
          location,
          budget,
          schedule,
          description,
          contactEmail,
        } = req.body;
        const updatedFields = { updatedAt: new Date() };

        if (subject !== undefined) updatedFields.subject = subject.trim();
        if (classLevel !== undefined)
          updatedFields.classLevel = classLevel.trim();
        if (location !== undefined) updatedFields.location = location.trim();
        if (budget !== undefined && budget !== "")
          updatedFields.budget = Number(budget);
        if (schedule !== undefined) updatedFields.schedule = schedule.trim();
        if (description !== undefined)
          updatedFields.description = description.trim();
        if (contactEmail !== undefined)
          updatedFields.contactEmail = contactEmail.trim();

        // 7. Nothing to update?
        if (Object.keys(updatedFields).length === 1) {
          return res
            .status(400)
            .send({ error: "No valid fields provided for update" });
        }

        // 8. Update post
        const result = await tuitionPostsCollection.findOneAndUpdate(
          { _id: postId },
          { $set: updatedFields },
          { returnDocument: "after" }
        );

        res.send({
          success: true,
          message: "Tuition post updated successfully",
          updatedPost: result.value,
        });
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: "Internal server error" });
      }
    });

    // PATCH /tuition-posts/admin/:id (Admin approve / reject tuition posts)
    app.patch(
      "/tuition-posts/admin/:id",
      verifyFBToken,
      verifyAdmin(usersCollection),
      async (req, res) => {
        try {
          const { id } = req.params;

          if (!ObjectId.isValid(id)) {
            return res.status(400).send({ error: "Invalid tuition post ID" });
          }

          const postId = new ObjectId(id);

          const existingPost = await tuitionPostsCollection.findOne({
            _id: postId,
          });

          if (!existingPost) {
            return res.status(404).send({ error: "Tuition post not found" });
          }

          if (existingPost.isDeleted) {
            return res
              .status(400)
              .send({ error: "Cannot update a deleted post" });
          }

          // Only pending posts can be moderated
          if (existingPost.status !== "admin-pending") {
            return res.status(400).send({
              error: `Post already ${existingPost.status.replace(
                "admin-",
                ""
              )}`,
            });
          }

          const { status } = req.body;
          console.log("Incoming status:", req.body.status);

          const allowedStatuses = ["admin-approved", "admin-rejected"];
          if (!allowedStatuses.includes(status)) {
            return res.status(400).send({
              error:
                "Invalid status. Must be 'admin-approved' or 'admin-rejected'.",
            });
          }

          const update = {
            status,
            updatedAt: new Date(),
          };

          if (status === "admin-approved") {
            update.adminApprovedAt = new Date();
          }

          if (status === "admin-rejected") {
            update.adminRejectedAt = new Date();
          }

          const result = await tuitionPostsCollection.findOneAndUpdate(
            { _id: postId },
            { $set: update },
            { returnDocument: "after" }
          );

          res.send({
            success: true,
            message: `Tuition post ${status.replace(
              "admin-",
              ""
            )} successfully`,
            updatedPost: result.value,
          });
        } catch (err) {
          console.error(err);
          res.status(500).send({ error: "Internal server error" });
        }
      }
    );

    // DELETE tuition posts
    app.delete("/tuition-posts/:id", verifyFBToken, async (req, res) => {
      try {
        const id = req.params.id;
        const fbEmail = req.user?.email;

        if (!fbEmail) {
          return res.status(400).send({ error: "Invalid authentication" });
        }

        // Validate ObjectId
        if (!ObjectId.isValid(id)) {
          return res.status(400).send({ error: "Invalid tuition post ID" });
        }
        const postId = new ObjectId(id);

        // Fetch existing post
        const existingPost = await tuitionPostsCollection.findOne({
          _id: postId,
        });
        if (!existingPost) {
          return res.status(404).send({ error: "Tuition post not found" });
        }

        // Ownership check
        if (existingPost.userEmail !== fbEmail) {
          return res.status(403).send({ error: "Forbidden. Not your post." });
        }

        // Soft-delete guard
        if (existingPost.isDeleted) {
          return res
            .status(400)
            .send({ error: "Tuition post already withdrawn" });
        }

        // 1. Soft-delete the tuition post
        const result = await tuitionPostsCollection.updateOne(
          { _id: postId },
          {
            $set: {
              isDeleted: true,
              deletedAt: new Date(),
              status: "cancelled",
              updatedAt: new Date(),
            },
          }
        );

        // 2. Soft-delete related applications instead of removing them
        await tuitionApplicationsCollection.updateMany(
          { tuitionPostId: postId, isDeleted: { $ne: true } },
          {
            $set: {
              isDeleted: true,
              deletedAt: new Date(),
              status: "cancelled",
              updatedAt: new Date(),
            },
          }
        );

        res.send({
          success: true,
          message:
            "Tuition post and related applications withdrawn successfully",
          modifiedCount: result.modifiedCount,
        });
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: "Internal server error" });
      }
    });

    /* =========================================================
       APPLICATIONS APIs
    ========================================================== */
    // GET all applications (student view) with pagination
    app.get("/applications", verifyFBToken, async (req, res) => {
      try {
        const studentEmail = req.user.email;
        const search = req.query.search?.trim();
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;

        // Base pipeline
        const basePipeline = [
          { $match: { studentEmail } },

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
            $match: {
              $or: [
                { "applications.isDeleted": { $ne: true } },
                { applications: { $eq: null } },
              ],
            },
          },
          ...(search
            ? [
                {
                  $match: {
                    $or: [
                      {
                        "applications.tutorName": {
                          $regex: search,
                          $options: "i",
                        },
                      },
                      { tuitionCode: { $regex: search, $options: "i" } },
                      {
                        "applications.qualifications": {
                          $regex: search,
                          $options: "i",
                        },
                      },
                      {
                        "applications.qualifications": {
                          $regex: search,
                          $options: "i",
                        },
                      },
                      {
                        "applications.experience": {
                          $regex: search,
                          $options: "i",
                        },
                      },
                      {
                        "applications.status": {
                          $regex: search,
                          $options: "i",
                        },
                      },
                    ],
                  },
                },
              ]
            : []),

          {
            $project: {
              _id: { $ifNull: ["$applications._id", "$_id"] },
              applicationCode: "$applications.applicationCode",
              tutorId: "$applications.tutorId",
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
        ];

        // Count total matching documents
        const totalResult = await tuitionPostsCollection
          .aggregate([...basePipeline, { $count: "total" }])
          .toArray();
        const total = totalResult[0]?.total || 0;

        // Apply sorting, skip & limit for pagination
        const applications = await tuitionPostsCollection
          .aggregate([
            ...basePipeline,
            { $sort: { createdAt: -1 } },
            { $skip: skip },
            { $limit: limit },
          ])
          .toArray();

        res.send({
          success: true,
          page,
          limit,
          total,
          applications,
        });
      } catch (err) {
        console.error("GET /applications error:", err);
        res.status(500).send({ success: false, message: "Server error" });
      }
    });

    // GET all applications created by the logged-in tutor (paginated)
    app.get(
      "/applications/my-applications",
      verifyFBToken,
      async (req, res) => {
        try {
          const tutorEmail = req.user.email;
          const search = req.query.search?.trim();
          const page = parseInt(req.query.page) || 1;
          const limit = parseInt(req.query.limit) || 20;
          const skip = (page - 1) * limit;

          const basePipeline = [
            // Only this tutor's applications
            {
              $match: {
                tutorEmail,
                isDeleted: { $ne: true },
              },
            },
            // Join tuition post
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
            // Response structure
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
            // Search filter
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
          ];

          // Count total matching documents
          const totalResult = await tuitionApplicationsCollection
            .aggregate([...basePipeline, { $count: "total" }])
            .toArray();
          const total = totalResult[0]?.total || 0;

          // Apply sort, skip & limit for pagination
          const applications = await tuitionApplicationsCollection
            .aggregate([
              ...basePipeline,
              { $sort: { createdAt: -1 } },
              { $skip: skip },
              { $limit: limit },
            ])
            .toArray();

          res.send({
            success: true,
            page,
            limit,
            total,
            applications,
          });
        } catch (err) {
          console.error("GET /applications/my-applications error:", err);
          res.status(500).send({ success: false, message: "Server error" });
        }
      }
    );

    // POST /applications - Create Tutor Application
    app.post("/applications", verifyFBToken, async (req, res) => {
      try {
        const { tuitionPostId, qualifications, experience, expectedSalary } =
          req.body;
        const fbEmail = req.user.email;

        /* -------------------- 1. Verify tutor -------------------- */
        const user = await usersCollection.findOne({ email: fbEmail });

        if (!user || user.role !== "tutor") {
          return res.status(403).send({ error: "Only tutors can apply" });
        }

        const tutorProfile = await tutorCollection.findOne({
          userId: user._id,
        });

        if (!tutorProfile) {
          return res.status(403).send({
            error: "Tutor profile not found. Complete your profile first.",
          });
        }

        if (tutorProfile.tutorStatus !== "approved") {
          return res.status(403).send({
            error: "Tutor is not approved by admin yet.",
          });
        }
        /* -------------------- 2. Validate input -------------------- */
        if (
          !tuitionPostId ||
          !qualifications ||
          !experience ||
          !expectedSalary
        ) {
          return res.status(400).send({ error: "Missing required fields" });
        }

        let tuitionPostObjectId;
        try {
          tuitionPostObjectId = new ObjectId(tuitionPostId);
        } catch {
          return res.status(400).send({ error: "Invalid tuitionPostId" });
        }

        /* -------------------- 3. Fetch tuition post -------------------- */
        const tuitionPost = await tuitionPostsCollection.findOne({
          _id: tuitionPostObjectId,
        });

        if (!tuitionPost) {
          return res.status(404).send({ error: "Tuition post not found" });
        }

        /* -------------------- 4. Prevent duplicate application -------------------- */
        const exists = await tuitionApplicationsCollection.findOne({
          tuitionPostId: tuitionPostObjectId,
          tutorId: tutor._id,
        });

        if (exists) {
          return res
            .status(409)
            .send({ error: "Already applied to this tuition" });
        }

        /* -------------------- 5. Generate application code -------------------- */
        const applicationCode = await getNextCode("applicationCode", "TA");
        const now = new Date();

        /* -------------------- 6. Create application -------------------- */
        const newApplication = {
          applicationCode,

          tuitionPostId: tuitionPostObjectId,

          // student (analytics + authorization) ✅ fixed field names
          studentId: tuitionPost.studentId || null,
          studentEmail: tuitionPost.studentEmail || null,

          // tutor
          tutorId: tutor._id,
          tutorName: tutor.name,
          tutorEmail: tutor.email,
          tutorPhoto: tutor.photoURL || null,

          // application details
          qualifications,
          experience,
          expectedSalary: Number(expectedSalary),
          finalSalary: null,

          // payment linkage (future)
          paymentId: null,

          // status & timestamps
          status: "pending",
          createdAt: now,
          updatedAt: now,
          approvedAt: null,
          rejectedAt: null,
          paidAt: null,
        };

        const result = await tuitionApplicationsCollection.insertOne(
          newApplication
        );

        res.send({
          success: true,
          message: "Application submitted successfully",
          applicationId: result.insertedId,
          applicationCode,
        });
      } catch (err) {
        console.error("POST /applications error:", err);
        res.status(500).send({ error: "Internal server error" });
      }
    });

    // PATCH — Approve application (Student only)
    app.patch("/applications/approve/:id", verifyFBToken, async (req, res) => {
      try {
        const applicationId = req.params.id;
        const fbEmail = req.user.email;

        if (!ObjectId.isValid(applicationId)) {
          return res.status(400).send({ error: "Invalid application id" });
        }

        const application = await tuitionApplicationsCollection.findOne({
          _id: new ObjectId(applicationId),
        });

        if (!application) {
          return res.status(404).send({ error: "Application not found" });
        }

        if (application.status !== "pending") {
          return res.status(400).send({
            error: "Only pending applications can be approved",
          });
        }

        // Fetch tuition post
        const tuitionPost = await tuitionPostsCollection.findOne({
          _id: new ObjectId(application.tuitionPostId),
        });

        if (!tuitionPost) {
          return res.status(404).send({ error: "Tuition post not found" });
        }

        // Ownership check
        if (tuitionPost.userEmail !== fbEmail) {
          return res.status(403).send({ error: "Unauthorized action" });
        }

        // Approve selected application
        await tuitionApplicationsCollection.updateOne(
          { _id: application._id },
          {
            $set: {
              status: "approved",
              finalSalary: application.expectedSalary,
              approvedAt: new Date(),
              updatedAt: new Date(),
            },
          }
        );

        // Reject all other pending applications for this tuition
        await tuitionApplicationsCollection.updateMany(
          {
            tuitionPostId: application.tuitionPostId,
            status: "pending",
            _id: { $ne: application._id },
          },
          {
            $set: {
              status: "rejected",
              rejectedAt: new Date(),
              updatedAt: new Date(),
            },
          }
        );

        // Update tuition post state
        await tuitionPostsCollection.updateOne(
          { _id: tuitionPost._id },
          {
            $set: {
              status: "approved",
              approvedAt: new Date(),
            },
          }
        );

        res.send({
          success: true,
          message: "Tutor application approved",
        });
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: "Internal server error" });
      }
    });

    // PATCH — Reject application (Student only)
    app.patch("/applications/reject/:id", verifyFBToken, async (req, res) => {
      try {
        const applicationId = req.params.id;
        const fbEmail = req.user.email;

        const application = await tuitionApplicationsCollection.findOne({
          _id: new ObjectId(applicationId),
        });

        if (!application) {
          return res.status(404).send({ error: "Application not found" });
        }

        if (application.status !== "pending") {
          return res.status(400).send({
            error: "Only pending applications can be rejected",
          });
        }

        const tuitionPost = await tuitionPostsCollection.findOne({
          _id: new ObjectId(application.tuitionPostId),
        });

        if (!tuitionPost) {
          return res.status(404).send({ error: "Tuition post not found" });
        }

        if (tuitionPost.userEmail !== fbEmail) {
          return res.status(403).send({ error: "Unauthorized action" });
        }

        await tuitionApplicationsCollection.updateOne(
          { _id: application._id },
          {
            $set: {
              status: "rejected",
              rejectedAt: new Date(),
              updatedAt: new Date(),
            },
          }
        );

        res.send({
          success: true,
          message: "Application rejected",
        });
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: "Internal server error" });
      }
    });

    // PATCH - Tutor edits their own application (PENDING only)
    app.patch(
      "/applications/tutor-update/:id",
      verifyFBToken,
      async (req, res) => {
        try {
          const appId = req.params.id;
          const fbEmail = req.user.email;

          // Validate ObjectId
          if (!ObjectId.isValid(appId)) {
            return res.status(400).send({ error: "Invalid application id" });
          }

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
              .send({ error: "You are not allowed to edit this application" });
          }

          // Status guard
          if (application.status !== "pending") {
            return res.status(400).send({
              error: "Only pending applications can be edited",
            });
          }

          const { qualifications, experience, expectedSalary } = req.body;

          const updatedFields = {
            updatedAt: new Date(),
          };

          // Update only provided fields
          if (qualifications !== undefined) {
            updatedFields.qualifications = qualifications;
          }

          if (experience !== undefined) {
            updatedFields.experience = experience;
          }

          if (expectedSalary !== undefined) {
            const salary = Number(expectedSalary);
            if (Number.isNaN(salary) || salary <= 0) {
              return res
                .status(400)
                .send({ error: "Expected salary must be a valid number" });
            }
            updatedFields.expectedSalary = salary;
          }

          // Nothing to update
          if (Object.keys(updatedFields).length === 1) {
            return res
              .status(400)
              .send({ error: "No valid fields provided for update" });
          }

          const result = await tuitionApplicationsCollection.updateOne(
            { _id: application._id },
            { $set: updatedFields }
          );

          res.send({
            success: true,
            message: "Application updated successfully",
            modifiedCount: result.modifiedCount,
          });
        } catch (err) {
          console.error(err);
          res.status(500).send({ error: "Internal server error" });
        }
      }
    );

    // DELETE - Tutor withdraws their own application (PENDING only)
    app.delete("/applications/:id", verifyFBToken, async (req, res) => {
      try {
        const appId = req.params.id;
        const fbEmail = req.user.email;

        // Validate ObjectId
        if (!ObjectId.isValid(appId)) {
          return res.status(400).send({ error: "Invalid application id" });
        }

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

        // Status guard
        if (application.status !== "pending") {
          return res.status(400).send({
            error: "Only pending applications can be withdrawn",
          });
        }

        // Already deleted?
        if (application.isDeleted) {
          return res.status(400).send({
            error: "Application already withdrawn",
          });
        }

        const result = await tuitionApplicationsCollection.updateOne(
          { _id: application._id },
          {
            $set: {
              isDeleted: true,
              deletedAt: new Date(),
            },
          }
        );

        res.send({
          success: true,
          message: "Application withdrawn successfully",
          modifiedCount: result.modifiedCount,
        });
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: "Internal server error" });
      }
    });

    /* =========================================================
       PAYMENT Related APIs
    ========================================================== */
    // POST /payment-checkout-session
    app.post("/payment-checkout-session", verifyFBToken, async (req, res) => {
      try {
        const paymentInfo = req.body;
        const studentEmail = req.user.email;

        // 1. Validate expectedSalary
        const expectedSalary = Number(paymentInfo.expectedSalary);
        if (Number.isNaN(expectedSalary) || expectedSalary <= 0) {
          return res.status(400).send({ error: "Invalid expectedSalary" });
        }

        // 2. Fetch the application
        const application = await tuitionApplicationsCollection.findOne({
          _id: new ObjectId(paymentInfo.applicationId),
          tutorId: new ObjectId(paymentInfo.tutorId),
          isDeleted: { $ne: true },
        });

        if (!application) {
          return res
            .status(404)
            .send({ error: "Application not found or withdrawn" });
        }

        // 3. Include studentId in metadata
        const studentId = application.studentId;

        // 4. Create Stripe checkout session
        const session = await stripe.checkout.sessions.create({
          line_items: [
            {
              price_data: {
                currency: "BDT",
                unit_amount: expectedSalary * 100,
                product_data: {
                  name: `Payment to Tutor: ${paymentInfo.tutorName} for Tuition: ${paymentInfo.tuitionTitle}`,
                },
              },
              quantity: 1,
            },
          ],
          customer_email: studentEmail,
          mode: "payment",
          metadata: {
            tuitionPostId: paymentInfo.tuitionPostId,
            applicationId: paymentInfo.applicationId,
            tutorId: paymentInfo.tutorId,
            tutorEmail: paymentInfo.tutorEmail,
            studentId: studentId.toString(),
            tuitionCode: paymentInfo.tuitionCode,
            tuitionTitle: paymentInfo.tuitionTitle,
          },
          success_url: `${process.env.SITE_DOMAIN}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
          cancel_url: `${process.env.SITE_DOMAIN}/dashboard/payment-cancelled`,
        });

        res.send({ url: session.url });
      } catch (error) {
        console.error("Error creating payment checkout session:", error);
        res.status(500).send({
          success: false,
          message: "Failed to create payment session",
        });
      }
    });

    // PATCH /verify-payment-success
    app.patch("/verify-payment-success", verifyFBToken, async (req, res) => {
      try {
        const sessionId = req.query.session_id;
        if (!sessionId) {
          return res
            .status(400)
            .send({ success: false, message: "Missing session_id" });
        }

        const session = await stripe.checkout.sessions.retrieve(sessionId);

        if (session.payment_status !== "paid") {
          return res.send({ success: false, message: "Payment not completed" });
        }

        const {
          tuitionPostId,
          applicationId,
          tutorId,
          tutorEmail,
          studentId,
          tuitionTitle,
          tuitionCode,
        } = session.metadata || {};

        if (!tuitionPostId || !applicationId || !tutorId || !studentId) {
          return res
            .status(400)
            .send({ success: false, message: "Invalid session metadata" });
        }

        const paidAt = new Date();

        const [
          tuitionPostObjectId,
          applicationObjectId,
          tutorObjectId,
          studentObjectId,
        ] = [tuitionPostId, applicationId, tutorId, studentId].map(
          (id) => new ObjectId(id)
        );

        // Fetch tuition post and application
        const tuitionPost = await tuitionPostsCollection.findOne({
          _id: tuitionPostObjectId,
          isDeleted: { $ne: true },
        });
        const application = await tuitionApplicationsCollection.findOne({
          _id: applicationObjectId,
          isDeleted: { $ne: true },
        });

        if (!tuitionPost || !application) {
          return res.status(404).send({
            success: false,
            message: "Tuition post or application not found",
          });
        }

        // Update tuition post to 'paid'
        await tuitionPostsCollection.updateOne(
          { _id: tuitionPostObjectId },
          {
            $set: {
              status: "paid",
              paidAt,
              approvedAt: paidAt,
              updatedAt: paidAt,
            },
          }
        );

        const amount = session.amount_total / 100;
        const platformFee = Number((amount * 0.1).toFixed(2));
        const tutorEarning = Number((amount - platformFee).toFixed(2));

        // Approve selected tutor
        await tuitionApplicationsCollection.updateOne(
          { _id: applicationObjectId },
          {
            $set: {
              status: "paid",
              paymentStatus: "paid",
              finalSalary: tutorEarning,
              paidAt,
              approvedAt: paidAt,
              updatedAt: paidAt,
            },
          }
        );

        // Reject other pending tutors
        await tuitionApplicationsCollection.updateMany(
          {
            tuitionPostId: tuitionPostObjectId,
            status: "pending",
            _id: { $ne: applicationObjectId },
          },
          {
            $set: { status: "rejected", rejectedAt: paidAt, updatedAt: paidAt },
          }
        );

        // Save payment record if not exists
        const fullTransactionId = session.payment_intent;
        const displayTransactionId = `ETB-${fullTransactionId
          .slice(-8)
          .toUpperCase()}`;

        let payment = await paymentCollection.findOne({
          transactionId: fullTransactionId,
        });

        if (!payment) {
          const result = await paymentCollection.insertOne({
            tuitionPostId: tuitionPostObjectId,
            applicationId: applicationObjectId,
            tutorId: tutorObjectId,
            studentId: studentObjectId,
            tuitionTitle: tuitionTitle || null,
            tuitionCode: tuitionCode || null,
            tutorEmail,
            customer_email: session.customer_email,
            amount,
            platformFee,
            tutorEarning,
            currency: session.currency,
            transactionId: fullTransactionId,
            displayTransactionId,
            paymentGateway: "stripe",
            paymentStatus: "paid",
            purpose: "tutor_application_payment",
            paidAt,
            createdAt: paidAt,
          });

          // Link payment to application
          await tuitionApplicationsCollection.updateOne(
            { _id: applicationObjectId },
            { $set: { paymentId: result.insertedId } }
          );

          payment = await paymentCollection.findOne({ _id: result.insertedId });
        } else {
          // Ensure the application has the paymentId set if not already
          if (!application.paymentId) {
            await tuitionApplicationsCollection.updateOne(
              { _id: applicationObjectId },
              { $set: { paymentId: payment._id } }
            );
          }
        }

        return res.send({
          success: true,
          message: "Payment verified successfully",
          payment,
        });
      } catch (error) {
        console.error("Verify payment error:", error);
        res
          .status(500)
          .send({ success: false, message: "Internal server error" });
      }
    });

    // GET payments for Payment History (student)
    app.get("/payments", verifyFBToken, async (req, res) => {
      try {
        const fbEmail = req.user?.email;
        if (!fbEmail) {
          return res
            .status(400)
            .send({ success: false, message: "Invalid authentication" });
        }

        // Pagination params
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;

        // Optional date filters
        const fromDate = req.query.from ? new Date(req.query.from) : null;
        const toDate = req.query.to ? new Date(req.query.to) : null;

        // Optional search filter
        const search = req.query.search?.trim();

        const query = {
          customer_email: fbEmail,
          isDeleted: { $ne: true },
        };

        if (fromDate || toDate) {
          query.paidAt = {};
          if (fromDate) query.paidAt.$gte = fromDate;
          if (toDate) query.paidAt.$lte = toDate;
        }

        if (search) {
          query.$or = [
            { tuitionTitle: { $regex: search, $options: "i" } },
            { tuitionCode: { $regex: search, $options: "i" } },
          ];
        }

        const totalPayments = await paymentCollection.countDocuments(query);

        const payments = await paymentCollection
          .find(query)
          .sort({ paidAt: -1 })
          .skip(skip)
          .limit(limit)
          .toArray();

        res.send({
          success: true,
          page,
          limit,
          total: totalPayments,
          payments,
        });
      } catch (error) {
        console.error("Fetch payment history error:", error);
        res
          .status(500)
          .send({ success: false, message: "Failed to fetch payment history" });
      }
    });

    // GET tutor ongoing tuitions with search & pagination
    app.get("/tutor/ongoing-tuitions", verifyFBToken, async (req, res) => {
      try {
        const tutorEmail = req.user.email;
        if (!tutorEmail) {
          return res
            .status(400)
            .send({ success: false, message: "Invalid authentication" });
        }

        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;

        const fromDate = req.query.from ? new Date(req.query.from) : null;
        const toDate = req.query.to ? new Date(req.query.to) : null;
        const search = req.query.search?.trim();

        // Base match stage
        const matchStage = {
          tutorEmail,
          status: "paid",
          isDeleted: { $ne: true },
        };
        if (fromDate || toDate) {
          matchStage.paidAt = {};
          if (fromDate) matchStage.paidAt.$gte = fromDate;
          if (toDate) matchStage.paidAt.$lte = toDate;
        }

        const pipeline = [
          { $match: matchStage },

          // Lookup payment
          {
            $lookup: {
              from: "payments",
              localField: "paymentId",
              foreignField: "_id",
              as: "payment",
            },
          },
          { $unwind: { path: "$payment", preserveNullAndEmptyArrays: true } },

          // Only include paid payments or null (for manual/edge cases)
          {
            $match: {
              $or: [
                { "payment.paymentStatus": "paid" },
                { payment: { $eq: null } },
              ],
              "payment.isDeleted": { $ne: true },
            },
          },

          // Lookup student
          {
            $lookup: {
              from: "users",
              localField: "payment.customer_email",
              foreignField: "email",
              as: "student",
            },
          },
          { $unwind: { path: "$student", preserveNullAndEmptyArrays: true } },

          // Lookup tuition to get tuitionCode
          {
            $lookup: {
              from: "tuitions",
              localField: "tuitionPostId",
              foreignField: "_id",
              as: "tuition",
            },
          },
          { $unwind: { path: "$tuition", preserveNullAndEmptyArrays: true } },

          // Search filter
          ...(search
            ? [
                {
                  $match: {
                    $or: [
                      { "student.name": { $regex: search, $options: "i" } },
                      { "student.email": { $regex: search, $options: "i" } },
                      {
                        "payment.tuitionTitle": {
                          $regex: search,
                          $options: "i",
                        },
                      },
                      {
                        "tuition.tuitionCode": {
                          $regex: search,
                          $options: "i",
                        },
                      },
                    ],
                  },
                },
              ]
            : []),

          // Project final fields
          {
            $project: {
              _id: 1,
              applicationCode: 1,
              tuitionPostId: 1,
              tuitionCode: "$tuition.tuitionCode",
              status: 1,
              createdAt: 1,
              tuitionTitle: "$payment.tuitionTitle",
              amountPaid: "$payment.amount",
              tutorEarning: { $multiply: ["$payment.amount", 0.9] },
              studentName: "$student.name",
              studentEmail: "$student.email",
              studentPhone: "$student.phone",
            },
          },

          { $sort: { createdAt: -1 } },
          { $skip: skip },
          { $limit: limit },
        ];

        // Fetch ongoing tuitions
        const ongoingTuitions = await tuitionApplicationsCollection
          .aggregate(pipeline)
          .toArray();

        // Count total matching documents (without skip & limit)
        const countPipeline = pipeline.filter(
          (stage) => !stage.$skip && !stage.$limit
        );
        countPipeline.push({ $count: "total" });
        const countResult = await tuitionApplicationsCollection
          .aggregate(countPipeline)
          .toArray();
        const totalCount = countResult[0]?.total || 0;

        res.send({
          success: true,
          page,
          limit,
          total: totalCount,
          ongoingTuitions,
        });
      } catch (err) {
        console.error("Fetch ongoing tuitions error:", err);
        res.status(500).send({
          success: false,
          message: "Failed to fetch ongoing tuitions",
        });
      }
    });

    // GET Tutor revenue history with search & pagination
    app.get("/tutor/revenue", verifyFBToken, async (req, res) => {
      try {
        const tutorEmail = req.user.email;
        if (!tutorEmail) {
          return res
            .status(400)
            .send({ success: false, message: "Invalid authentication" });
        }

        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;
        const search = req.query.search?.trim();

        const fromDate = req.query.from ? new Date(req.query.from) : null;
        const toDate = req.query.to ? new Date(req.query.to) : null;

        // Base query
        const query = {
          tutorEmail,
          paymentStatus: "paid",
          isDeleted: { $ne: true },
        };

        if (fromDate || toDate) {
          query.paidAt = {};
          if (fromDate) query.paidAt.$gte = fromDate;
          if (toDate) query.paidAt.$lte = toDate;
        }

        // If search is provided, add $or condition
        if (search) {
          query.$or = [
            { tuitionTitle: { $regex: search, $options: "i" } },
            { studentEmail: { $regex: search, $options: "i" } },
          ];
        }

        // Count total matching documents
        const totalCount = await paymentCollection.countDocuments(query);

        // Fetch paginated records
        const revenueRecords = await paymentCollection
          .find(query)
          .sort({ paidAt: -1 })
          .skip(skip)
          .limit(limit)
          .toArray();

        res.send({
          success: true,
          page,
          limit,
          total: totalCount,
          revenueRecords,
        });
      } catch (err) {
        console.error("Fetch tutor revenue error:", err);
        res
          .status(500)
          .send({ success: false, message: "Failed to fetch tutor revenue" });
      }
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
