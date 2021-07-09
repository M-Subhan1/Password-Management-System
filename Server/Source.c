#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<ctype.h>
#include<time.h>
#include<conio.h>
#include<windows.h>

#define MAX_USERNAME_LEN 10
#define MAX_PASSWORD_LENGTH 20
#define MAX_EMAIL_LENGTH 30
#define MAX_EMAIL_TYPE_LENGTH 15
#define USER_LOGIN_FORMAT "%s %s %d\n"
#define ENTRY_FORMAT "%s %s %s %s\n"
#define USER_DATA "users.dat"
#define ENTRIES_DATA "data.dat"
#define BUFFER_SIZE 256

typedef struct Entry {
    char username[MAX_USERNAME_LEN + 1];
    char email_type[MAX_EMAIL_TYPE_LENGTH + 1];
    char email_address[MAX_EMAIL_LENGTH + 1];
    char password[MAX_PASSWORD_LENGTH + 1];
} Entry;

typedef struct User {
    char username[MAX_USERNAME_LEN + 1];
    char password[MAX_PASSWORD_LENGTH + 1];
    int status;
} User;

int login_menu(void); // program startup menu
int login(char[]);  // validates login
int sign_up(char []); // adds a new user
int main_menu(char[]); // renders menu
int admin_menu(char[]); //  admin menu 
int user_menu(char[]); // user menu
int add_entries(char[]);  // make new entries
void view_entries(char[]); // view entries made by the current user
int delete_entries(char[]); // delete entries
int remove_users(); // Deactivates an account removes all stored data for the user in question
int strength_check(); // tests password strength and suggests improvements
int generate_password(void); // generates random, strong passwords
void account_lock_menu();  // account lock toggle menu
void account_lock_toggle(char[], int); // revokes / grants the said user's permissions ( 0 - revoke, 1 - grant)
void encrypt(const char*); // encrypts the file
void decrypt(const char*); // decrypts the file

// UTILITY FUNCTIONS
void get_details(char[], int); // custom input function that ignores spaces, tabs, newline characters
void get_password(char[]);  // custom input function to hide passwords during input
void clear_input_stream(void); // clears the input stream
void goto_xy(int, int); // helps style the output
void print_xy(const char*, int, int); // helps style the output

int main(void)
{
    //encrypt("users.dat");
    //encrypt("data.dat");
    while (login_menu());
    //decrypt("users.dat");
    //decrypt("data.dat");
}

int login_menu()
{
    char username[MAX_USERNAME_LEN + 1] = ""; // stores username (if logged in) for use in the program
    int logged_in, running = 1;
    char option;

    while (running) // Helps with looping over the menu when other functions return
    {
        // Printing the options with some styling
        system("@cls || clear");
        print_xy(" -------------------------------", 44, 2);
        print_xy(" LOGIN MENU \n", 55, 3);
        print_xy(" -------------------------------\n", 44, 4);
        print_xy("Welcome! Please choose a suitable option.", 40 ,7);
        print_xy("\t1 - Login", 40, 9);
        print_xy("\t2 - Sign Up", 40, 10);
        print_xy("\t3 - Exit", 40, 11);
        print_xy("\t  ? ", 40 , 12);

        while (1) 
        {
            option = getchar(); // user selection
            clear_input_stream(); // removing the newline char from input stream

            if (option == '1')
            {
                logged_in = login(username); // setting the user status to logged in, after successful login
                break;
            }

            else if (option == '2')
            {
                logged_in = sign_up(username); // setting the user status to logged in (after successful signup)
                break;
            }

            else if (option == '3')
                exit(EXIT_SUCCESS);
        }

        if (logged_in) // if user loggged in, we render the main menu till the program is exited
            running = main_menu(username); 
    }
    
    return 1; 
}

// User Related function
int login(char username[])
{
    char password[MAX_PASSWORD_LENGTH + 1] = {'\0'};
    int tries = 0, temp, match;

    FILE* file_read;
    User user;

    while (1)
    {
        // Printing sign in menu
        system("@cls || clear");
        print_xy("------------------------------ - \n", 44, 2);
        print_xy("  SIGN IN \n", 55, 3);
        print_xy(" -------------------------------\n", 44, 4);

        // Taking user input
        print_xy("Username: ", 50, 7);
        get_details(username, MAX_USERNAME_LEN);

        print_xy("Password: ", 50, 9);
        get_password(password);

        decrypt(USER_DATA); // preparing file for validation

        fopen_s(&file_read, USER_DATA, "r"); // opening the user data file
        if (file_read == NULL)
            exit(EXIT_FAILURE); // terminating the program if error accessing the file

        rewind(file_read), match = 0, tries++; // rewinding the file cursor to init pos, matches to zero, tries++ for every iteration

        while (!feof(file_read)) // looping till file end of file
        {
            temp = fscanf(file_read, USER_LOGIN_FORMAT, user.username, user.password, &user.status); // extracting a line of data from file and storing in  
            // if login details valid and (tries < 4 or the user is an admin) regular users can only sign in for < 4 tries
            if (strcmp(username, user.username) == 0 && strcmp(password, user.password) == 0 && (strcmp(username, "admin") == 0 || tries <= 3)) 
            {
                fclose(file_read); // closing the file and encrypting data before exiting the program/ function
                encrypt(USER_DATA);

                if (user.status == 1) // (status == 1: account has permissions, status == 0: account access revoked)
                {
                    goto_xy(35, 15);
                    printf("Welcome, %s! Press any key to continue...", user.username);
                    temp = _getch();
                    return user.status; // if login details valid, returning user status for processing
                }
                else {
                    goto_xy(25, 15);
                    printf("%s, contact your administrator to regain access to your account..\n\n", user.username);
                    exit(EXIT_SUCCESS);
                }
            }
            else if (strcmp(username, user.username) == 0) // if the said username exists, match++
            {
                match++;
                break;
            }
        }
        
        fclose(file_read); // closing the file and encrypting it
        encrypt(USER_DATA); 

        if (tries >= 3 && match && strcmp(username, "admin") != 0) // locks the account of the matched user (if tries exceed 3)
        {
            fclose(file_read);
            account_lock_toggle(username, 0);
            print_xy("Your account has been locked! Contact your administrator.", 30, 15);
            print_xy("Press any key to exit...", 40, 17); 
            if(_getch())
                exit(EXIT_SUCCESS); // terminating the program
        }

        else if (tries >= 5) // if tries exceed the limit, program exits
        {
            print_xy("Try again later! Program terminating...\n\n", 42, 15);
            Sleep(750);
            exit(EXIT_SUCCESS); // terminating the program after a short delay
        }

        else
        {
            print_xy("Invalid login details, try again.", 42, 15);
            Sleep(750); // re-rendering the menu after a short delay
        }
    }

    return 0;
} 

int sign_up(char username[])
{
    char temp_username[MAX_USERNAME_LEN + 1] = {'\0'}, password[MAX_PASSWORD_LENGTH + 1] = { '\0' }, password_confirm[MAX_PASSWORD_LENGTH + 1] = { '\0' }, buffer[256] = { '\0' };
    User user_buffer = { '\0' };
    FILE *file_read, *file_write;
    int entries_found, char_read, temp, option;

    while (1)
    {
        system("@cls || clear");
        print_xy(" -------------------------------\n", 44, 2);
        print_xy("  SIGN UP \n", 55, 3);
        print_xy(" -------------------------------\n", 44, 4);

        // Getting the selected username (ensuring it is valid)
        print_xy("Choose a username (4 - 10 characters):  ", 45, 7);
        get_details(temp_username, MAX_USERNAME_LEN); // does not allow spaces/tabs or characters greater than the number specified

        if (strlen(temp_username) < 4 || strlen(temp_username) > MAX_USERNAME_LEN)
        {
            goto_xy(40, 15);
            printf("Choose a valid username (4-10 characters)");
            Sleep(750);
            continue;
        }

        // Getting the password (ensuring it is within parameters) and getting the user to confirm it
        print_xy("Enter a password (6-20 characters):  ", 45, 9);
        get_password(password);

        if (strlen(password) < 6 || strlen(password) > MAX_PASSWORD_LENGTH)
        {
            goto_xy(40,15);
            printf("Choose a valid password (6-20 characters)");
            Sleep(750);
            continue;
        }

        print_xy("Confirm your password:  ", 45, 11);
        get_password(password_confirm);

        // preparing file for data validation
        decrypt(USER_DATA);
        fopen_s(&file_read, USER_DATA, "r");

        if (file_read == NULL)
            exit(EXIT_FAILURE);

        entries_found = 0; // setting match to zero for each iteration

        while (!feof(file_read)) // looping over file
        {
            // storing a line of data from the file into buffer struct for processing
            char_read = fscanf(file_read, USER_LOGIN_FORMAT, user_buffer.username, user_buffer.password, &user_buffer.status); 

            if (strcmp(temp_username, user_buffer.username) == 0) // if the selected username already exists in database, entries++
                entries_found++;
        }

        fclose(file_read); // closing and encrypting the file
        encrypt(USER_DATA);

        if (!entries_found) // if no entries found (username not taken)
        {
            if (strcmp(password, password_confirm) == 0) // and passwords match
            {
                decrypt(USER_DATA); // preparing file for data entry
                fopen_s(&file_write, USER_DATA, "a");

                if (file_write == NULL)
                    exit(EXIT_FAILURE);

                strcpy(username, temp_username); //copying the username (from temp) to pointer provided by the main fucntion so it can be used elsewhere in the program
                // Creating a valid format specified string, writing it to the file, closing and encrypting the file
                sprintf_s(buffer, BUFFER_SIZE, USER_LOGIN_FORMAT, username, password, 1);
                fwrite(buffer, sizeof(char), strlen(buffer), file_write);
                fclose(file_write);
                encrypt(USER_DATA);

                print_xy("Successfully signed up, do you want to continue using the app? y for yes, any other key to exit the program..", 5, 15);
                option = _getch();
                if (option != 'Y' && option != 'y')
                    exit(EXIT_SUCCESS);

                return 1;
            }
            else // if passwords do not match and user wished to continue, running the func
            {
                print_xy("The passwords do not match! Press y to try again... any other key to exit to the main menu.", 15, 15);
                temp = _getch();
                if (temp != 'Y' && temp != 'y')
                    break;
            }
        }
        else // if entries found, letting the user know that username is already taken
        {
            print_xy("Username is already taken, choose a different one.\n", 35, 15);
            Sleep(1000);
        }
    }

    return 0;
}

int remove_users()
{
    char buffer_write[256] = { '\0' }, username[MAX_EMAIL_TYPE_LENGTH] = { '\0' };
    FILE* file_read, * file_write;
    User buffer_user;
    Entry buffer_entry;
    int temp, res = 1;

    decrypt(USER_DATA);
    fopen_s(&file_read, USER_DATA, "r");
    fopen_s(&file_write, "users_temp.dat", "a");

    if (file_read == NULL || file_write == NULL)
        exit(EXIT_FAILURE);

    // Printing the menu
    system("@cls || clear");

    print_xy(" -------------------------------", 44, 2);
    print_xy("  MANAGE USER ACCESS", 50, 3);
    print_xy(" -------------------------------", 44, 4);

    print_xy("Enter username of the account you wish to deactivate: ", 30, 8);
    get_details(username, MAX_USERNAME_LEN);
    
    while (1)
    {

        if (feof(file_read))
            break;

        temp = fscanf(file_read, USER_LOGIN_FORMAT, buffer_user.username, buffer_user.password, &buffer_user.status);

        if (strcmp(username, buffer_user.username) == 0 && strcmp(username, "admin") != 0)
            continue;
        else
        {
            sprintf_s(buffer_write, 256, USER_LOGIN_FORMAT, buffer_user.username, buffer_user.password, buffer_user.status);
            fwrite(buffer_write, sizeof(char), strlen(buffer_write), file_write);
        }
    }
    // cleanup (closing the files, encrypting)
    fclose(file_read);
    fclose(file_write);
    remove(USER_DATA);
    res = rename("users_temp.dat", USER_DATA);
    encrypt(USER_DATA);

    if (res != 0)
        exit(EXIT_FAILURE);

    // Deleting all stored entries for the user

    // preparing files for processing
    decrypt(ENTRIES_DATA);
    fopen_s(&file_read, ENTRIES_DATA, "r");
    fopen_s(&file_write, "data_temp.dat", "a");

    if (file_read == NULL || file_write == NULL)
        exit(EXIT_FAILURE);

    while (1)
    {
        if (feof(file_read))
            break;

        temp = fscanf(file_read, ENTRY_FORMAT, buffer_entry.username, buffer_entry.email_type, buffer_entry.email_address, buffer_entry.password);

        if (strcmp(username, buffer_entry.username) == 0)
            continue;

        sprintf_s(buffer_write, 256, ENTRY_FORMAT, buffer_entry.username, buffer_entry.email_type, buffer_entry.email_address, buffer_entry.password);
        fwrite(buffer_write, sizeof(char), strlen(buffer_write), file_write);
    }

    //cleanup (closing files, encrypting files)
    fclose(file_read);
    fclose(file_write);
    remove(ENTRIES_DATA);
    res = rename("data_temp.dat", ENTRIES_DATA);
    encrypt(ENTRIES_DATA);

    print_xy("Would you like to delete more user accounts? Press y to continue, any other key to return to the main menu..", 7, 15);

    temp = _getch();
    if (temp == 'Y' || temp == 'y')
        return 1;

    return 0;
}

void account_lock_toggle(char username[], int status)
{
    char buffer_write[256];
    FILE* file_read, * file_write;
    User buffer_user;
    int temp, res = 1;

    // processing files for data manipulation
    decrypt(USER_DATA);
    fopen_s(&file_read, USER_DATA, "r");
    fopen_s(&file_write, "users_temp.dat", "a");

    if (file_read == NULL || file_write == NULL)
        exit(EXIT_FAILURE);

    while (!feof(file_read))
    {
        // extracting each entry in a buffer struct
        temp = fscanf(file_read, USER_LOGIN_FORMAT, buffer_user.username, buffer_user.password, &buffer_user.status); 
       // if the buffer matches username, changing its status to the one provided
        if (strcmp(buffer_user.username, username) == 0 && strcmp("admin", username) != 0)
            buffer_user.status = status;
        // writing the struct to a new file
        sprintf_s(buffer_write, 256, USER_LOGIN_FORMAT, buffer_user.username, buffer_user.password, buffer_user.status); 
        fwrite(buffer_write, sizeof(char), strlen(buffer_write), file_write);
    }

    // Cleanup (closing opened files, encrypting files)
    fclose(file_read);
    fclose(file_write);
    remove(USER_DATA);
    res = rename("users_temp.dat", USER_DATA); // making the temp file to be our database file 
    encrypt(USER_DATA);

    if (res != 0) // program terminates with error
        exit(EXIT_FAILURE);

}

void account_lock_menu()
{
    char username[MAX_USERNAME_LEN + 1] = { '\0' };
    int option, temp;

    while (1)
    {
        // Printing the menu
        system("@cls || clear");
        print_xy(" -------------------------------", 44, 2);
        print_xy("  MANAGE USER ACCESS", 50, 3);
        print_xy(" -------------------------------", 44, 4);
        print_xy("Welcome! Please choose a suitable option.", 40, 7);
        print_xy("\t1 - Lock a user", 40, 9);
        print_xy("\t2 - Unlock user", 40, 10);
        print_xy("\t3 - Main Menu", 40, 11);
        print_xy("\t  ? ", 40, 12);

        // getting user input
        option = getchar();
        clear_input_stream();

        if (option == '1' || option == '2')
            break;

        else if (option == '3') 
            return; // returning to the prev menu
    }

    if (option == '1') // printing menu based on selected option
    {
        while (1)
        {
            // printing 
            system("@cls || clear");
            print_xy(" -------------------------------", 44, 2);
            print_xy("  REVOKE USER ACCESS", 50, 3);
            print_xy(" -------------------------------", 44, 4);
            // getting username to revoke permissions
            print_xy("Enter the user you want to deny access to: ", 35, 8);
            get_details(username, MAX_USERNAME_LEN);

            if (strcmp(username, "admin") == 0) // admin cannot lock himself out
            {
                print_xy("Cannot lock yourself out!!", 45, 10);
                Sleep(500);
            }
            else
                break;
        }
        // calling the func with status = 1, denies access
        account_lock_toggle(username, 0);
        print_xy("Account successfully locked! ", 27, 15);
    }

    else 
    {
        system("@cls || clear");
        goto_xy(44, 2);
        printf(" -------------------------------");
        goto_xy(50, 3);
        printf("  GRANT USER ACCESS");
        goto_xy(44, 4);
        printf(" -------------------------------");
        goto_xy(35, 8);
        // getting username to restore access to
        printf("Enter the user you want to grant access to: ");
        get_details(username, MAX_USERNAME_LEN);
        // calling the func with status = 1, restores access
        account_lock_toggle(username, 1);

        goto_xy(26, 15);
        printf("Account successfully unlocked! ");
    }

    printf("Press any key to return to the main menu...");
    temp = _getch();
} //

// Menu related
int main_menu(char user[]) {
    if (strcmp(user, "admin") == 0) // renders menu depending on the user
        return admin_menu(user);
    else
        return user_menu(user);
}

int admin_menu(char user[])
{
    while (1)
    {
        int option = 0;

        while (1) // Printing the admin menu
        {
            system("@cls || clear");
            print_xy(" -------------------------------\n", 44, 2);
            print_xy(" MAIN MENU \n", 55, 3);
            print_xy(" -------------------------------\n", 44, 4);
            print_xy("Welcome! Please choose a suitable option.\n", 40, 7);
            print_xy("\t1 - Add an entry\n", 40, 9);
            print_xy("\t2 - View your previous entries\n", 40, 10);
            print_xy("\t3 - Delete an entry\n", 40, 11);
            print_xy("\t4 - Generate a random password\n", 40, 12);
            print_xy("\t5 - Check Password strength\n", 40, 13);
            print_xy("\t6 - Remove users\n", 40, 14);
            print_xy("\t7 - Manage user access\n", 40, 15);
            print_xy("\t8 - Log out\n", 40, 16);
            print_xy("\t9 - Exit\n", 40, 17);
            print_xy("\t  ? ", 40, 18);

            scanf_s("%d", &option); // user input
            clear_input_stream();
            if ((option <= 9 && option >= 0)) // breaking out, if input is valid 
                break;

            goto_xy(43, 21);
            printf("Invalid selection! Try again!");
            Sleep(750); // pausing the system for 750ms before clearing the screen in the next loop
        }

        switch (option) // calling the desired function
        {
        case 1:
            while (add_entries(user));
            break;
        case 2:
            view_entries(user); // calling the func once since it renders all the entries
            break;
        case 3: 
            while (delete_entries(user));  // keeps calling the function till func returns 0
            break;
        case 4:
            while (generate_password());  // keeps calling the function till func returns 0
            break;
        case 5:
            while (strength_check()); // keeps calling the function till func returns 0
            break;
        case 6:
            while (remove_users()); // keeps calling the function till func returns 0
            break;
        case 7:
            account_lock_menu(); // calls account_lock menu once
            break;
        case 8:
            return 1; // returning
        case 9:
            exit(EXIT_SUCCESS); // terminates the program
        }
    }
}

int user_menu(char user[])
{
    while (1)
    {
        int option = 0;
        // Printing the user menu
        while (1)
        {
            system("@cls || clear");
            print_xy(" -------------------------------\n", 44, 2);
            print_xy(" MAIN MENU \n", 55, 3);
            print_xy(" -------------------------------\n", 44, 4);
            print_xy("Welcome! Please choose a suitable option.\n", 40, 7);
            print_xy("\t1 - Add an entry\n", 40, 9);
            print_xy("\t2 - View your previous entries\n", 40, 10);
            print_xy("\t3 - Delete an entry\n", 40, 11);
            print_xy("\t4 - Generate a random password\n", 40, 12);
            print_xy("\t5 - Check Password strength\n", 40, 13);
            print_xy("\t6 - Log out\n", 40, 14);
            print_xy("\t7 - Exit\n", 40, 15);
            print_xy("\t  ? ", 40, 16);

            scanf_s("%d", &option);
            clear_input_stream();
            if ((option <= 7 && option >= 1)) // breaking out, if input is valid 
                break;

            print_xy("Invalid selection! Try again!", 43, 18);
            Sleep(750);
        }

        switch (option) 
        {
        case 1:
            while (add_entries(user)); // keeps calling the function till func returns 0
            break;
        case 2:
            view_entries(user); // keeps calling the function till func returns 0
            break;
        case 3:
            while (delete_entries(user)); // keeps calling the function till func returns 0
            break;
        case 4:
            while (generate_password()); // keeps calling the function till func returns 0
            break;
        case 5:
            while (strength_check()); // keeps calling the function till func returns 0
            break;
        case 6:
            return 1; // returns to the prev menu
        case 7:
            exit(EXIT_SUCCESS); // teminates the program
        }
    }
}

// Data manipulation
void view_entries(char user[])
{
    FILE* file_read;
    Entry entry;
    int char_read, entries_found = 0, temp;
    int print_x = 15, print_y = 10;

    // Styling the menu
    system("@cls || clear");
    print_xy(" -------------------------------", 44, 2);
    print_xy(" VIEW ENTRIES \n", 55, 3);
    print_xy(" -------------------------------", 44, 4);
    print_xy("\t Username\t\tType\t\t\tEmail\t\t\tPassword", 15, 6);
    print_xy("*****************************************************************************************\n", 15, 8);

    // processing the file for data entry
    decrypt(ENTRIES_DATA);
    fopen_s(&file_read, ENTRIES_DATA, "r");

    if (file_read == NULL)
        exit(EXIT_FAILURE);

    while (1) // parsing the data and printing each entry
    {
        if (feof(file_read))
            break;

        char_read = fscanf(file_read, ENTRY_FORMAT, entry.username, entry.email_type, entry.email_address, entry.password);
        
        if (strcmp(user, entry.username) == 0)
        {
            entries_found++;
            goto_xy(print_x, print_y += 2);
            printf("%s\t%15s\t%30s\t%20s", entry.username, entry.email_type, entry.email_address, entry.password);
        }
    }                  

    if (!entries_found)
        printf("\t\t\t\t\t\tNo entries found!");
    // cleaning up (closing, encrypting)
    fclose(file_read);
    encrypt(ENTRIES_DATA);
    printf("\n\n\n\n\n\t\t\t\tPress any key to go back to the previous menu..");
    temp = _getch();
}

int add_entries(char user[])
{
    Entry buffer_entry;
    FILE* file_write;
    char buffer[BUFFER_SIZE] = { '\0' }, buffer_password[MAX_PASSWORD_LENGTH + 1] = { '\0' };
    int temp;

    while (1)
    {
        system("@cls || clear");

        print_xy("---------------------------------------------------", 34, 2);
        print_xy(" ADD ENTRIES \n", 55, 3);
        print_xy("---------------------------------------------------", 34, 4);
        // getting desired data from the user
        print_xy("Enter email type: ", 45, 7);
        get_details(buffer_entry.email_type, MAX_EMAIL_TYPE_LENGTH);

        print_xy("Enter email address: ", 45, 9);
        get_details(buffer_entry.email_address, MAX_EMAIL_LENGTH);

        print_xy("Input your password: ", 45, 11);
        get_password(buffer_entry.password);

        print_xy("Confirm your password: ", 45, 13);
        get_password(buffer_password);

        if (strcmp(buffer_password, buffer_entry.password) == 0)
            break;

        print_xy("The passwords do not match! Please try again.", 37, 15);
        Sleep(750);
    }
    // preparing file for data entry
    decrypt(ENTRIES_DATA);
    fopen_s(&file_write, ENTRIES_DATA, "a");
    if (file_write == NULL)
        exit(EXIT_FAILURE);
    // writing to the file and closing / encrypting
    sprintf_s(buffer, BUFFER_SIZE, ENTRY_FORMAT, user, buffer_entry.email_type, buffer_entry.email_address, buffer_entry.password); // making a formatted buffer string
    fwrite(buffer, sizeof(char), strlen(buffer), file_write); // writing the buffer string
    fclose(file_write);
    encrypt(ENTRIES_DATA);

    print_xy("Would you like to add more entries? Press y to continue, any other key to return to the main menu.", 7 ,18);
    temp = _getch();

    if (temp == 'Y' || temp == 'y')
        return 1;

    return 0;
}

int delete_entries(char user[])
{
    char buffer_write[BUFFER_SIZE] = { '\0' }, email_type[MAX_EMAIL_TYPE_LENGTH + 1] = { '\0' }, email[MAX_EMAIL_LENGTH + 1] = {'\0'};
    FILE* file_read, * file_write;
    Entry buffer_entry;
    int temp, res = 1;

    // printing the menu
    system("@cls || clear");
    print_xy("---------------------------------------------------", 34, 2);
    print_xy(" DELETE ENTRIES \n", 55, 3);
    print_xy("---------------------------------------------------", 34, 4);

    print_xy("Email type: ", 45, 7);
    get_details(email_type, MAX_EMAIL_TYPE_LENGTH);
    print_xy("Email address: ", 45, 9);
    get_details(email, MAX_EMAIL_LENGTH);
    decrypt(ENTRIES_DATA);
    fopen_s(&file_read, ENTRIES_DATA, "r");
    fopen_s(&file_write, "data_temp.dat", "a");

    if (file_read == NULL || file_write == NULL)
        exit(EXIT_FAILURE);

    while (!feof(file_read))
    {
        temp = fscanf(file_read, ENTRY_FORMAT, buffer_entry.username, buffer_entry.email_type, buffer_entry.email_address, buffer_entry.password);
        if (strcmp(user, buffer_entry.username) == 0 && strcmp(email_type, buffer_entry.email_type) == 0 && strcmp(email, buffer_entry.email_address) == 0)
            continue; // when entry is matched, skipping over to the next entry (deleteing the matched entry)

        // writing the struct back to the file
        sprintf_s(buffer_write, BUFFER_SIZE, ENTRY_FORMAT,
            buffer_entry.username, buffer_entry.email_type, buffer_entry.email_address, buffer_entry.password); // making a formatted buffer
        fwrite(buffer_write, sizeof(char), strlen(buffer_write), file_write); // writing the buffer
    }
    // cleaning up (closing files, encrypting decrypted data)
    fclose(file_read);
    fclose(file_write);
    remove(ENTRIES_DATA);
    res = rename("data_temp.dat", ENTRIES_DATA);
    encrypt(ENTRIES_DATA);

    if (res != 0)
        exit(EXIT_FAILURE);

    // if user wants to continue returns 1 (while loop in main casues the function to run again)
    print_xy("Would you like to delete more entries? Press y to continue, any other key to return to the main menu..", 7, 18);
    temp = _getch();

    if (temp == 'Y' || temp == 'y')
        return 1;

    return 0;
}

int strength_check()
{
    int digits = 0, lowercase = 0, uppercase = 0, special = 0, length;
    char password[MAX_PASSWORD_LENGTH + 1], temp;

    system("@cls || clear");

    print_xy(" -------------------------------\n", 44, 2);
    print_xy(" PASSWORD TEST \n", 55, 3);
    print_xy(" -------------------------------\n", 44, 4);

    print_xy("Enter the password you want to test: ", 37, 8);
    get_password(password);

    length = (int)strlen(password);
    password[20] = '\0';
    // extracting the count of each type of character
    for (int i = 0; i < length; i++)
    {
        if (isupper(password[i]))
            uppercase++;
        else if (islower(password[i]))
            lowercase++;
        else if (isdigit(password[i]))
            digits++;
        else
            special++;
    }
    // Printing status and suggestions to strengthen the password 
    print_xy("Status: ", 50, 9);

    if (length >= 8 && digits && lowercase && uppercase && special)
        printf("Strong\n");

    else if (lowercase && uppercase && special)
    {
        printf("Moderate\n");
        print_xy("Consider including digits and increasing password length.", 42, 11);
    }

    else
    {
        printf("Weak\n");
        print_xy("Consider the following changes: ", 42, 11);
        print_xy("  Include digits", 42, 13);
        print_xy("  Include special characters", 42, 14);
        print_xy("  Include uppercase characters", 42, 15);
        print_xy("  Include lowercase characters", 42, 16);
    }
    
    print_xy("Would you like to test another password? Press y to continue, any other key to return to the menu..", 14, 18);
    temp = _getch();
    if (temp == 'Y' || temp == 'y')
        return 1;

    return 0;
}

int generate_password()
{
    int digit = 2, lowercase = 2, uppercase = 2, special = 2, length, randIndex, temp;
    char password[MAX_PASSWORD_LENGTH + 1] = {'\0'}, buffer = '\0';

    // randomly assigning each character type (2-5)
    srand((int)time(NULL));
    lowercase += rand() % 4;
    uppercase += rand() % 4;
    digit += rand() % 4;
    special += rand() % 4;

    length = lowercase + uppercase + digit + special;

    for (int i = 0; i < length; i++)
    {
        if (i < lowercase)
            buffer = rand() % ('z' - 'a' + 1) + 'a'; // random lowercase character

        else if (i < lowercase + uppercase)
            buffer = rand() % ('Z' - 'A' + 1) + 'A'; // random uppercase character

        else if (i < lowercase + uppercase + digit)
            buffer = rand() % ('9' - '0' + 1) + '0'; // random digit

        else if (i < lowercase + uppercase + digit + special) // random special
        {
            switch (rand() % 4)
            {
            case 0:
                buffer = (rand() % (15)) + 33; // 33 - 47 (range of special chars in ASCII table)
                break;
            case 1:
                buffer = (rand() % (7)) + 58; // 58 - 64 (range of special chars in ASCII table)
                break;
            case 2:
                buffer = (rand() % (6)) + 91; // 91 - 96 (range of special chars in ASCII table)
                break;
            case 3:
                buffer = (rand() % (4)) + 123; // 123 - 126 (range of special chars in ASCII table)
                break;
            }
        }

        randIndex = rand() % length; // randomly getting an index to store the buffer at
        while (1)
        {
            if (password[randIndex] == '\0') // if index empty store the char and break
            {
                password[randIndex] = buffer;
                break;
            }
            randIndex = ++randIndex % (length); // if index is not empty, check the next index
        }
    }

    // Printing to the screen
    system("@cls || clear");

    print_xy(" -------------------------------\n", 44, 2);
    print_xy("GENERATE PASSWORD \n", 52, 3);
    print_xy(" -------------------------------\n", 44, 4);
    goto_xy(43, 8);
    printf("Generated password: %s\n", password);
    // Getting user selection
    print_xy("Would you like to generate another password? Press y to continue, any other key to return to the main menu..", 7, 12);
    temp = _getch();
    if (temp == 'Y' || temp == 'y')
        return 1;

    return 0;
}

// Encryption / Decryption
void encrypt(const char* file_name)
{
    FILE* fp1, * fp2;
    char ch;
    int ren;

    // Opening files for processing
    fp1 = fopen(file_name, "r");
    fp2 = fopen("temp.dat", "w");

    if (fp1 == NULL || fp2 == NULL)
        exit(EXIT_FAILURE); // terminating with an error

    while (1) // goes over each character in the file till EOF char
    {
        ch = fgetc(fp1);

        if (ch == EOF)
            break;

        ch = ch - (8 * 5 - 3);
        fputc(ch, fp2);
    }
    // closing files and making the new file the primary file
    fclose(fp1);
    fclose(fp2);
    remove(file_name);
    ren = rename("temp.dat", file_name);

    if (ren != 0)
        exit(EXIT_FAILURE);
}

void decrypt(const char* file_name)
{
    FILE* fp1, * fp2;
    int ren;
    char ch;

    fp1 = fopen(file_name, "r");
    fp2 = fopen("temp.dat", "w");

    if (fp2 == NULL || fp1 == NULL)
        exit(EXIT_FAILURE);

    while (1) // goes over each character in the file till EOF char
    {
        ch = fgetc(fp1);

        if (ch == EOF)
            break;

        ch = ch + (8 * 5 - 3); // char shifting
        fputc(ch, fp2); // writing to a new file
    }
    // closing files and making the new file the primary file
    fclose(fp1);
    fclose(fp2);
    remove(file_name);
    ren = rename("temp.dat", file_name);

    if (ren != 0)
        exit(EXIT_FAILURE);
}

// UTILITY FUNCTIONS
void get_password(char password[])
{
    const int ENTER = 13, BKSPC = 8, TAB = 9, SPACE = 32;
    int index = 0;
    char buffer = '\0';

    while (index < MAX_PASSWORD_LENGTH)
    {
        buffer = _getch();
        if (buffer == ENTER) // when enter encountered, places null char at the curr index, loop terminated
        {
            password[index] = '\0';
            break;
        }
        else if (buffer == BKSPC)
        {
            if (index > 0)
            {
                printf("\b \b"); // removing printed char from screen
                index--; // decreasing index for bksp,
            }
        }
        else if (buffer == TAB || buffer == SPACE)
        {
            continue;
        }
        else // adds the character to buffer and echoes a * to the screen
        {
            password[index++] = buffer; 
            printf("*");
        }
    }
    password[MAX_PASSWORD_LENGTH] = '\0'; // ensuring that the string is null terminated
}

void get_details(char details[], int max_length)
{
    const int ENTER = 13, BKSPC = 8, TAB = 9, SPACE = 32;
    int index = 0;
    char buffer = '\0';

    while (index < max_length)
    {
        buffer = _getch();
        if (buffer == ENTER) // when enter encountered, places null char at the curr index, loop is terminated, 
        {
            details[index] = '\0';
            break;
        }
        else if (buffer == BKSPC)
        {
            if (index > 0)  
            {
                printf("\b \b"); // removing printed char from screen
                index--; // decreasing index for bksp,
            }
        }
        else if (buffer == TAB || buffer == SPACE)
            continue;

        else // adds the character to buffer and echoes it to the screen
        {
            details[index++] = buffer;
            printf("%c", buffer);
        }
    }

    details[max_length] = '\0'; // ensuring that the string is null terminated
}

void clear_input_stream(void)
{
    while (getchar() != '\n'); // extracts all of the data till new line char is encountered
}

void print_xy(const char* message, int x, int y)
{
    goto_xy(x , y);
    printf("%s", message);
}

void goto_xy(int x, int y)
{
    COORD position = { x,y };
    SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), position);
}