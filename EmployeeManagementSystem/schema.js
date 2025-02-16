const { 
    GraphQLObjectType, GraphQLSchema, GraphQLString, 
    GraphQLID, GraphQLList, GraphQLFloat, GraphQLNonNull 
} = require('graphql');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('./models/User');
const Employee = require('./models/Employee');

// User Type
const UserType = new GraphQLObjectType({
    name: 'User',
    fields: () => ({
        id: { type: GraphQLID },
        username: { type: GraphQLString },
        email: { type: GraphQLString }
    })
});

// Employee Type
const EmployeeType = new GraphQLObjectType({
    name: 'Employee',
    fields: () => ({
        id: { type: GraphQLID },
        first_name: { type: GraphQLString },
        last_name: { type: GraphQLString },
        email: { type: GraphQLString },
        gender: { type: GraphQLString },
        designation: { type: GraphQLString },
        salary: { type: GraphQLFloat },
        date_of_joining: { type: GraphQLString },
        department: { type: GraphQLString },
        employee_photo: { type: GraphQLString },
        created_at: { type: GraphQLString }
    })
});

// Generate JWT Token Function
const generateToken = (user) => {
    return jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
};

// Root Query
const RootQuery = new GraphQLObjectType({
    name: 'RootQueryType',
    fields: {
        login: {
            type: GraphQLString, 
            args: {
                email: { type: GraphQLString },
                password: { type: GraphQLString }
            },
            async resolve(parent, args) {
                const user = await User.findOne({ email: args.email });
                if (!user) throw new Error("User not found");

                const isMatch = await bcrypt.compare(args.password, user.password);
                if (!isMatch) throw new Error("Incorrect password");

                return generateToken(user);
            }
        },
        getEmployees: {
            type: new GraphQLList(EmployeeType),
            async resolve(parent, args, context) {
                if (!context.user) throw new Error("Unauthorized access. Token required.");
                return await Employee.find();
            }
        },
        searchEmployee: {
            type: EmployeeType,
            args: { id: { type: GraphQLID } },
            async resolve(parent, args, context) {
                if (!context.user) throw new Error("Unauthorized access. Token required.");
                return await Employee.findById(args.id);
            }
        },
        searchEmployeeByDesignationOrDept: {
            type: new GraphQLList(EmployeeType),
            args: { designation: { type: GraphQLString }, department: { type: GraphQLString } },
            async resolve(parent, args, context) {
                if (!context.user) throw new Error("Unauthorized access. Token required.");
                return await Employee.find({
                    $or: [{ designation: args.designation }, { department: args.department }]
                });
            }
        }
    }
});

// Mutations
const Mutation = new GraphQLObjectType({
    name: 'Mutation',
    fields: {
        signup: {
            type: GraphQLString, // Returns only the JWT token
            args: {
                username: { type: GraphQLString },
                email: { type: GraphQLString },
                password: { type: GraphQLString }
            },
            async resolve(parent, args) {
                const existingUser = await User.findOne({ email: args.email });
                if (existingUser) throw new Error("Email is already registered.");

                const salt = await bcrypt.genSalt(10);
                const hashedPassword = await bcrypt.hash(args.password, salt);
                
                const newUser = new User({
                    username: args.username,
                    email: args.email,
                    password: hashedPassword
                });

                await newUser.save();
                return generateToken(newUser);
            }
        },
        addEmployee: {
            type: EmployeeType,
            args: {
                first_name: { type: GraphQLString },
                last_name: { type: GraphQLString },
                email: { type: GraphQLString },
                gender: { type: GraphQLString },
                designation: { type: GraphQLString },
                salary: { type: GraphQLFloat },
                date_of_joining: { type: GraphQLString },
                department: { type: GraphQLString },
                employee_photo: { type: GraphQLString }
            },
            async resolve(parent, args, context) {
                if (!context.user) throw new Error("Unauthorized access. Token required.");
                
                const employee = new Employee({ ...args });
                return await employee.save();
            }
        },
        updateEmployee: {
            type: EmployeeType,
            args: {
                id: { type: GraphQLID },
                first_name: { type: GraphQLString },
                last_name: { type: GraphQLString },
                email: { type: GraphQLString },
                gender: { type: GraphQLString },
                designation: { type: GraphQLString },
                salary: { type: GraphQLFloat },
                date_of_joining: { type: GraphQLString },
                department: { type: GraphQLString },
                employee_photo: { type: GraphQLString }
            },
            async resolve(parent, args, context) {
                if (!context.user) throw new Error("Unauthorized access. Token required.");
        
                // Set the updated_at timestamp to the current date
                args.updated_at = new Date().toISOString();
        
                return await Employee.findByIdAndUpdate(args.id, args, { new: true });
            }
        },
        
        deleteEmployee: {
            type: EmployeeType,
            args: { id: { type: GraphQLID } },
            async resolve(parent, args, context) {
                if (!context.user) throw new Error("Unauthorized access. Token required.");

                return await Employee.findByIdAndDelete(args.id);
            }
        }
    }
});

module.exports = new GraphQLSchema({
    query: RootQuery,
    mutation: Mutation
});
