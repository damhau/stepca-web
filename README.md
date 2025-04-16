# Step CA Admin

A web-based dashboard for managing [Step CA](https://smallstep.com/docs/step-ca) – the open-source certificate authority. Built with Flask and styled with AdminLTE, it provides an intuitive UI to manage ACME accounts, x.509 and SSH certificates, provisioners, and system services.

---

## Features

- **ACME Management**
  - List and manage ACME Accounts, Orders, Certificates, Authorizations, and Challenges.

- **X.509 Certificate Management**
  - View valid certificates.
  - View revoked certificates with detailed info and linked provisioners.

- **SSH Certificate Management**
  - View all issued SSH certificates.

- **Provisioner Management**
  - List, add, and delete JWK/ACME provisioners using `step ca provisioner`.

- **Admin Users**
  - View configured admin provisioners.

- **Step CA Config Editor**
  - Edit and validate the `ca.json` file with JSON syntax highlighting.

- **Systemd Service Control**
  - Start, stop, or restart the Step CA systemd service (with limited permissions).

- **Dashboard Overview**
  - Visual KPIs like number of active certs, revoked certs, provisioners, etc.

---

## Requirements

- Python 3.9+
- Linux with `systemd` (for service management)
- Step CA installed and configured
- A configured admin provisioner

---

## Project Structure

```
stepca-admin/
├── app.py
├── templates/
│   ├── layout.html
│   ├── dashboard.html
│   └── ...
├── static/
│   └── (CSS, JS, icons)
├── src/
│   ├── libs/
│   │   ├── cert_utils.py
│   │   ├── provisioner_utils.py
│   │   └── ...
├── requirements.txt
└── README.md
```

---

## Installation

1. **Clone the repository**

```bash
git clone https://github.com/youruser/stepca-admin.git
cd stepca-admin
```

2. **Create a virtual environment**

```bash
python3 -m venv venv
source venv/bin/activate
```

3. **Install dependencies**

```bash
pip install -r requirements.txt
```


4. **Run the app**

```bash
flask run
```

Then open your browser at: [http://localhost:5000](http://localhost:5000)

---

## Development

- Use the built-in Flask dev server for local testing.
- For UI, modify `templates/` and `static/` folders.
- To add new pages, extend `layout.html` and register routes in `app.py`.

---

## To Do / Ideas

- [ ] Add user authentication (basic auth or OAuth)
- [ ] Implement audit logging
- [ ] Add filtering and searching in tables
- [ ] Support bulk certificate operations
- [ ] UI for creating short-lived MTLS certs

---

## Contributing

Pull requests are welcome! For major changes, open an issue first to discuss what you’d like to change.

Please make sure to test and lint your code (`black`, `flake8`).

---

## License

MIT License — see `LICENSE` for details.

---

## Contact

Damien Hauser
damien@dhconsulting.ch

