#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <iostream>
#include <map>
#include <memory>
#include <ostream>
#include <string>
#include <vector>

#include <unistd.h>

using Clock = std::chrono::system_clock;
using TimePoint = std::chrono::time_point<Clock>;

class Item {
  std::string name;
  uint64_t id;
  uint64_t price;

public:
  Item(std::string &&name, uint64_t id, uint64_t price)
      : name(name), id(id), price(price) {}

  uint64_t getId() const { return id; }

  uint64_t getPrice() const { return price; }

  virtual std::string getName() const { return name; }

  friend bool operator==(const Item &left, const Item &right) {
    return left.getId() == right.getId();
  }

  virtual ~Item() = default;
};

class FoodItem : public Item {
  TimePoint expiry;

public:
  FoodItem(std::string &&name, uint64_t id, uint64_t price, TimePoint expiry)
      : Item(std::move(name), id, price), expiry(expiry) {}

  TimePoint &getExpiry() { return expiry; }

  std::string getName() const override {
    auto expiry_time = Clock::to_time_t(expiry);
    auto expiry_str = std::string(std::ctime(&expiry_time));
    expiry_str.pop_back();
    return Item::getName() + " (expires " + expiry_str + ")";
  }
};

class Catalogue {
  std::vector<std::shared_ptr<const Item>> items;

public:
  void addItem(Item *item) {
    if (std::find_if(items.begin(), items.end(), [item](auto &current_item) {
          return current_item->getId() == item->getId();
        }) != items.end()) {
      return;
    }

    items.emplace_back(item);
  }

  const Item *getItem(uint64_t id) {
    auto iter = std::find_if(items.begin(), items.end(),
                             [id](auto &item) { return item->getId() == id; });
    if (iter == items.end()) {
      return nullptr;
    } else {
      return iter->get();
    }
  }

  const auto begin() const { return items.begin(); }
  const auto end() const { return items.end(); }
};

class x {
  std::shared_ptr<const Item> item;
  uint64_t count;
  std::string notes;

public:
  CartEntry(const Item *item, uint64_t count = 1) : item(item), count(count) {}

  const std::shared_ptr<const Item> &getItem() const { return item; }

  uint64_t getCount() const { return count; }
  void setCount(uint64_t count) { this->count = count; }

  const std::string &getNotes() const { return notes; }
  void setNotes(std::string &&notes) { this->notes = std::move(notes); }
};

class Cart {
  std::vector<CartEntry> entries;

public:
  bool addItem(const Item *item) {
    assert(item);
    auto entry =
        std::find_if(entries.begin(), entries.end(),
                     [item](auto &entry) { return *entry.getItem() == *item; });
    if (entry != entries.end()) {
      return false;
    }

    entries.emplace_back(item);
    return true;
  }

  bool updateItem(uint64_t id, uint64_t count = 1) {
    auto entry =
        std::find_if(entries.begin(), entries.end(), [id](auto &entry) {
          return entry.getItem()->getId() == id;
        });
    if (entry == entries.end()) {
      return false;
    }

    entry->setCount(count);
    return true;
  }

  bool setNotes(uint64_t id, std::string &&notes) {
    auto entry =
        std::find_if(entries.begin(), entries.end(), [id](auto &entry) {
          return entry.getItem()->getId() == id;
        });
    if (entry == entries.end()) {
      return false;
    }

    entry->setNotes(std::move(notes));
    return true;
  }

  bool removeItem(uint64_t id) {
    auto new_end =
        std::remove_if(entries.begin(), entries.end(), [id](auto &entry) {
          return entry.getItem()->getId() == id;
        });
    if (new_end == entries.end()) {
      return false;
    } else {
      entries.erase(new_end, entries.end());
      return true;
    }
  }

  uint64_t getTotalPrice() {
    uint64_t totalPrice = 0;
    for (auto &entry : entries) {
      totalPrice += entry.getItem()->getPrice() * entry.getCount();
    }
    return totalPrice;
  }

  const auto begin() const { return entries.begin(); }
  const auto end() const { return entries.end(); }
};

static void ShowCatalogue(Catalogue &catalogue) {
  std::cout << "Catalogue:" << std::endl;

  for (const auto &item : catalogue) {
    std::cout << "- " << item->getId() << " - " << item->getName() << " - "
              << item->getPrice() << " euros" << std::endl;
  }
}

static void ShowCart(Cart &cart) {
  std::cout << "Cart:" << std::endl;

  for (const auto &entry : cart) {
    auto item = entry.getItem();
    std::cout << "- " << item->getId() << " - " << item->getName() << " - x"
              << entry.getCount() << " - " << entry.getNotes() << std::endl;
  }

  std::cout << "Total price: " << cart.getTotalPrice() << " euros" << std::endl;
}

enum class Command {
  Unknown,
  Exit,
  ShowCatalogue,
  ShowCart,
  AddItem,
  RemoveItem,
  SetCount,
  SetNotes,
  Pay,
};

static std::map<std::string, Command> descToCommand = {
    {"exit", Command::Exit},
    {"show catalogue", Command::ShowCatalogue},
    {"show cart", Command::ShowCart},
    {"add item", Command::AddItem},
    {"remove item", Command::RemoveItem},
    {"set count", Command::SetCount},
    {"set notes", Command::SetNotes},
    {"pay", Command::Pay},
};

void ListCommands() {
  std::cout << "Commands: " << std::endl;
  for (auto &command : descToCommand) {
    std::cout << "- " << command.first << std::endl;
  }
}

Command ParseCommand(std::string &command) {
  auto res = descToCommand.find(command);
  if (res != descToCommand.end()) {
    return res->second;
  } else {
    return Command::Unknown;
  }
}

Catalogue *InitializeCatalogue() {
  const auto day = std::chrono::hours(24);

  auto *catalogue = new Catalogue;

  catalogue->addItem(new Item("soap", 100, 4));
  catalogue->addItem(new Item("broom", 101, 20));
  catalogue->addItem(new Item("straws", 300, 1));
  catalogue->addItem(new FoodItem("milk", 400, 1, Clock::now() + day * 5));
  catalogue->addItem(new FoodItem("chips", 500, 2, Clock::now() + day * 150));
  catalogue->addItem(new FoodItem("oranges", 600, 3, Clock::now() + day * 20));
  catalogue->addItem(new FoodItem("carrots", 601, 1, Clock::now() + day * 45));

  return catalogue;
}

uint64_t ReadItemId() {
  std::cout << "Item ID > " << std::flush;
  uint64_t itemId;
  std::cin >> itemId;
  return itemId;
}

void AddItem(Catalogue *catalogue, Cart &cart) {
  auto itemId = ReadItemId();
  auto item = catalogue->getItem(itemId);
  if (!item) {
    std::cout << "Item not found" << std::endl;
    return;
  }

  cart.addItem(item);
}

void RemoveItem(Cart &cart) {
  auto itemId = ReadItemId();
  if (!cart.removeItem(itemId)) {
    std::cout << "Item not found in cart" << std::endl;
  }
}

void SetCount(Cart &cart) {
  auto itemId = ReadItemId();

  std::cout << "Item count > " << std::flush;
  uint64_t count;
  std::cin >> count;

  if (!cart.updateItem(itemId, count)) {
    std::cout << "Item not found" << std::endl;
  }
}

void SetNotes(Cart &cart) {
  auto itemId = ReadItemId();

  std::cout << "Notes > " << std::flush;
  std::string notes;
  std::getline(std::cin >> std::ws, notes);
  if (!cart.setNotes(itemId, std::move(notes))) {
    std::cout << "Item not found" << std::endl;
  }
}

int main() {
  if (setregid(getegid(), -1) == -1) {
    std::perror("setregid");
    std::exit(1);
  }

  auto *catalogue = InitializeCatalogue();

  Cart cart;
  std::string command_str;
  Command command = Command::Unknown;
  do {
    ListCommands();
    std::cout << "> " << std::flush;
    std::getline(std::cin >> std::ws, command_str);
    command = ParseCommand(command_str);

    switch (command) {
    case Command::Unknown:
      std::cout << "Unknown command" << std::endl;
      break;
    case Command::Exit:
      break;
    case Command::ShowCatalogue:
      ShowCatalogue(*catalogue);
      break;
    case Command::ShowCart:
      ShowCart(cart);
      break;
    case Command::AddItem:
      AddItem(catalogue, cart);
      break;
    case Command::RemoveItem:
      RemoveItem(cart);
      break;
    case Command::SetCount:
      SetCount(cart);
      break;
    case Command::SetNotes:
      SetNotes(cart);
      break;
    case Command::Pay:
      // TODO: Add payment methods
      std::cout << "Please pay: " << cart.getTotalPrice() << " euros"
                << std::endl;
      break;
    }

    std::cout << std::endl;
  } while (std::cin && command != Command::Exit);

  return 0;
}