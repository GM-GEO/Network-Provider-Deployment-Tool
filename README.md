# Provider Deployment Tool (Akbar)
The purpose of this tool is to deploy network objects that would normally be created through the Provider Dashboard by utilizing formatted CSVs.

## Supported Objects Per Provider
### FMC
1. Network
2. Network Group
3. URL
4. URL Group
5. URL Category
6. Security Zone
7. Port
8. Application
9. Host
10. FQDN

### Palo Alto Objects

# How to Use
The intent of this tool is to be packaged and deployed using Pyinstaller, which will run the main.py script that configures the network provider with the user input.

To run this code in an IDE, pull down the master branch and run the Main.py file

# Future Considerations
1. The ability to extract a selection of object types to use for migration
2. The ability to store resource definitions in an external file for ease of maintainence

## Resources
[FMC REST API Documentation](https://www.cisco.com/c/en/us/td/docs/security/firepower/620/api/REST/Firepower_Management_Center_REST_API_Quick_Start_Guide_620/Objects_in_the_REST_API.html)

[Pyinstaller](https://pyinstaller.org/en/stable/)
